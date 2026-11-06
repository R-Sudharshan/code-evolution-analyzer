#!/usr/bin/env bash
# Build the pinned, restricted tool image (httpx + WhatWeb + nuclei).
# ZAP is NOT in this image — it uses the upstream zaproxy image; see pull_zap_image.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

HTTPX_VERSION=${HTTPX_VERSION:-1.12.0}
NUCLEI_VERSION=${NUCLEI_VERSION:-3.8.0}
WHATWEB_VERSION=${WHATWEB_VERSION:-0.6.4}
TAG=${TAG:-pentai-tools:1.0.0}

echo "[*] Building $TAG (httpx=$HTTPX_VERSION whatweb=$WHATWEB_VERSION nuclei=$NUCLEI_VERSION)"
docker build \
  --platform linux/"$(uname -m | sed 's/aarch64/arm64/; s/x86_64/amd64/')" \
  --build-arg HTTPX_VERSION="$HTTPX_VERSION" \
  --build-arg WHATWEB_VERSION="$WHATWEB_VERSION" \
  --build-arg NUCLEI_VERSION="$NUCLEI_VERSION" \
  -f Dockerfile.tools \
  -t "$TAG" .

echo "[+] Verifying inside container (non-root):"
docker run --rm --user 10001:10001 "$TAG" sh -c 'httpx -version 2>&1 | head -1; whatweb --version 2>&1 | head -1; nuclei -version 2>&1 | head -1'
echo "[+] Image built: $TAG"
echo "[i] For OWASP ZAP, run deploy/scripts/pull_zap_image.sh (upstream zaproxy image, port/pinned separately)."
