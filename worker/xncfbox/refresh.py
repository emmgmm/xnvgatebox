#!/usr/bin/env python3
"""Build an xncfbox manifest without importing the VPS application.

This is deliberately a small, self-contained GitHub Actions tool.  It reads
the public VPN Gate CSV, asks the deployed xncfbox Worker to verify SSTP, and
writes only credential-free node evidence for the dedicated KV namespace.
"""
from __future__ import annotations

import base64
import csv
import io
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path


CSV_URLS = (
    "https://www.vpngate.net/api/iphone/",
    "https://download.vpngate.jp/api/iphone/",
)
HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.opengw\.net$", re.I)
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def fail(message: str) -> None:
    raise SystemExit("xncfbox refresh: " + message)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def public_ipv4(value: str) -> bool:
    if not isinstance(value, str) or not IP_RE.fullmatch(value):
        return False
    parts = [int(part) for part in value.split(".")]
    if any(part > 255 for part in parts):
        return False
    a, b, *_ = parts
    return a not in (0, 10, 127, 169, 192) and a < 224 and not (a == 100 and 64 <= b <= 127) and not (a == 172 and 16 <= b <= 31)


def int_value(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_csv(data: bytes) -> list[dict]:
    """Parse only the data columns needed by the Cloudflare refresh."""
    try:
        lines = data.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError:
        raise ValueError("csv_encoding") from None
    if len(lines) < 2 or lines[0].strip() != "*vpn_servers" or not lines[1].startswith("#HostName,"):
        raise ValueError("csv_format")
    reader = csv.DictReader(io.StringIO("\n".join([lines[1][1:]] + [line for line in lines[2:] if line and not line.startswith("*")])) )
    required = {"HostName", "CountryShort", "OpenVPN_ConfigData_Base64"}
    if not required.issubset(reader.fieldnames or set()):
        raise ValueError("csv_columns")
    candidates: dict[str, dict] = {}
    for row in reader:
        host = (row.get("HostName") or "").strip().lower()
        if "." not in host:
            host += ".opengw.net"
        if not HOST_RE.fullmatch(host):
            continue
        country = (row.get("CountryShort") or "").strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", country):
            country = "UN"
        encoded = row.get("OpenVPN_ConfigData_Base64") or ""
        # The profile is only used as a conservative signal that this is a
        # real VPN Gate row; it is never executed or published.
        try:
            if len(encoded) > 180_000:
                continue
            base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            continue
        item = {"hostname": host, "country": country, "score": int_value(row.get("Score"))}
        previous = candidates.get(host)
        if previous is None or item["score"] > previous["score"]:
            candidates[host] = item
    return sorted(candidates.values(), key=lambda item: (-item["score"], item["hostname"]))


def fetch_csv(timeout: float = 30.0) -> bytes:
    urls = tuple(filter(None, (os.getenv("XNCFBOX_CSV_URL", "").strip(), *CSV_URLS)))
    last_error = "csv_unavailable"
    for url in urls:
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "xncfbox-refresh/1"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = response.read(8_000_000)
            parse_csv(data)
            return data
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            last_error = type(exc).__name__.lower()
    fail(last_error)


def worker_origin() -> str:
    raw = os.getenv("WORKER_URL", "").strip().rstrip("/")
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        fail("invalid_worker_url")
    return "https://" + parsed.hostname + (":" + str(parsed.port) if parsed.port else "")


def check_node(origin: str, token: str, node: dict, timeout: float) -> dict | None:
    proxy = f"sstp://vpn:vpn@{node['hostname']}:443"
    url = origin + "/check?" + urllib.parse.urlencode({"proxy": proxy})
    observed: list[str] = []
    for _ in range(2):
        try:
            request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token, "User-Agent": "xncfbox-refresh/1"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read(64_000))
            if payload.get("type") != "sstp" or payload.get("success") is not True:
                return None
            if payload.get("hostname", "").lower() != node["hostname"] or payload.get("port") != 443:
                return None
            ip = (payload.get("exit") or {}).get("ip")
            if not public_ipv4(ip):
                return None
            observed.append(ip)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, TypeError):
            return None
    if len(observed) != 2 or observed[0] != observed[1]:
        return None
    now = utc_now()
    expires = now + timedelta(seconds=int(os.getenv("XNCFBOX_MANIFEST_TTL_SECONDS", "3600")))
    return {
        "node_id": "vpngate-" + re.sub(r"[^a-z0-9-]", "-", node["hostname"].lower()),
        "hostname": node["hostname"],
        "country": node["country"],
        "sstp_host": node["hostname"],
        "sstp_port": 443,
        "expected_exit_ip": observed[0],
        "actual_exit_ip": observed[1],
        "verified_at": iso(now),
        "expires_at": iso(expires),
        "ip_type": "unknown",
    }


def main() -> int:
    token = os.getenv("CHECKER_TOKEN", "").strip()
    if not token:
        fail("checker_token_missing")
    origin = worker_origin()
    candidate_limit = max(1, min(int(os.getenv("XNCFBOX_CANDIDATE_LIMIT", "20")), 100))
    max_nodes = max(1, min(int(os.getenv("XNCFBOX_MAX_NODES", "3")), 20))
    output = Path(os.getenv("CF_MANIFEST_PATH", "data/xncfbox/cf_manifest.json"))
    nodes = parse_csv(fetch_csv())[:candidate_limit]
    if not nodes:
        fail("no_candidates")
    verified: list[dict] = []
    workers = max(1, min(int(os.getenv("XNCFBOX_CHECK_CONCURRENCY", "3")), 8))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(check_node, origin, token, node, 35.0) for node in nodes]
        for future in as_completed(futures):
            result = future.result()
            if result:
                verified.append(result)
                if len(verified) >= max_nodes:
                    break
    if not verified:
        fail("no_verified_nodes")
    generated = utc_now()
    manifest = {
        "schema_version": 1,
        "kind": "vpngate_cf_validated_nodes",
        "generated_at": iso(generated),
        "expires_at": min(node["expires_at"] for node in verified),
        "scope": "tcp_ipv4_ws",
        "data_plane": {"base_path": "/"},
        "nodes": sorted(verified, key=lambda node: node["node_id"]),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": "passed", "candidates": len(nodes), "verified": len(verified), "output": str(output)}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except (ValueError, OSError, TypeError, KeyError):
        fail("invalid_input_or_filesystem_error")
