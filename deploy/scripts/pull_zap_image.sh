#!/usr/bin/env bash
# Pull the pinned upstream OWASP ZAP baseline image (requires Docker).
set -euo pipefail

ZAP_IMAGE=${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:2.17.0}

echo "[*] Pulling $ZAP_IMAGE"
docker pull "$ZAP_IMAGE"
echo "[+] Verifying invitation (zap-baseline.py -h):"
docker run --rm "$ZAP_IMAGE" zap-baseline.py -h >/dev/null
echo "[+] ZAP image ready: $ZAP_IMAGE"
echo "[i] ZAP baseline scan is passive — no active payloads are sent; the target must still be authorized and in scope."
