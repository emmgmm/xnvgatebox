#!/usr/bin/env python3
"""Publish one complete xncfbox manifest to its dedicated KV namespace."""
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
    token = os.getenv("CF_API_TOKEN", "")
    account = os.getenv("CF_ACCOUNT_ID", "")
    namespace = os.getenv("CF_KV_NAMESPACE_ID", "")
    if not token or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", account) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", namespace):
        fail("cloudflare_credentials_missing")
    key = urllib.parse.quote("manifest:current", safe="")
    url = f"https://api.cloudflare.com/client/v4/accounts/{account}/storage/kv/namespaces/{namespace}/values/{key}"
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
    if not isinstance(payload, dict) or payload.get("success") is not True:
        fail("cloudflare_rejected")
    print(json.dumps({"status": "published", "nodes": len(manifest["nodes"])}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except (OSError, ValueError, TypeError, KeyError):
        fail("invalid_input_or_filesystem_error")
