#!/usr/bin/env python3
"""Publish one complete xncfbox manifest through the dedicated Worker."""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit("xncfbox publish: " + message)


def main() -> int:
    path = Path(os.getenv("CF_MANIFEST_PATH", "data/xncfbox/cf_manifest.json"))
    if not path.is_file():
        fail("manifest_missing")
    try:
        manifest = json.loads(path.read_text())
        expiry = datetime.fromisoformat(manifest["expires_at"].replace("Z", "+00:00"))
    except (OSError, ValueError, TypeError, KeyError):
        fail("manifest_invalid")
    if manifest.get("schema_version") != 1 or manifest.get("kind") != "vpngate_cf_validated_nodes":
        fail("manifest_schema_mismatch")
    if not isinstance(manifest.get("nodes"), list) or not manifest["nodes"] or expiry <= datetime.now(timezone.utc):
        fail("manifest_empty_or_expired")
    flattened = json.dumps(manifest, ensure_ascii=False).lower()
    if any(field in flattened for field in ('"password"', '"token"', '"secret"', '"vless_uuid"')):
        fail("manifest_contains_secret_field")
    token = os.getenv("ADMIN_TOKEN", "")
    origin = os.getenv("WORKER_URL", "").strip().rstrip("/")
    parsed = urllib.parse.urlsplit(origin)
    if not token or parsed.scheme != "https" or not parsed.hostname or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        fail("worker_credentials_missing")
    url = "https://" + parsed.hostname + (":" + str(parsed.port) if parsed.port else "") + "/api/manifest"
    request = urllib.request.Request(url, data=path.read_bytes(), method="PUT", headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "User-Agent": "xncfbox-publish/1",
    })
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read(64_000))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        fail("cloudflare_request_failed")
    if not isinstance(payload, dict) or payload.get("status") != "published":
        fail("worker_rejected")
    print(json.dumps(payload))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except (OSError, ValueError, TypeError, KeyError):
        fail("invalid_input_or_filesystem_error")
