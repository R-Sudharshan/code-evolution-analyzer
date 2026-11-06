#!/usr/bin/env bash
# Build the pinned, restricted tool image (httpx + nuclei only).
set -euo pipefail
cd "$(dirname "$0")/.."

HTTPX_VERSION=${HTTPX_VERSION:-1.12.0}
NUCLEI_VERSION=${NUCLEI_VERSION:-3.8.0}
TAG=${TAG:-pentai-tools:1.0.0}

echo "[*] Building $TAG (httpx=$HTTPX_VERSION nuclei=$NUCLEI_VERSION)"
docker build \
  --platform linux/"$(uname -m | sed 's/aarch64/arm64/; s/x86_64/amd64/')" \
  --build-arg HTTPX_VERSION="$HTTPX_VERSION" \
  --build-arg NUCLEI_VERSION="$NUCLEI_VERSION" \
  -f Dockerfile.tools \
  -t "$TAG" .

echo "[+] Verifying inside container (non-root):"
docker run --rm --user 10001:10001 "$TAG" sh -c 'httpx -version 2>&1 | head -1; nuclei -version 2>&1 | head -1'
echo "[+] Image built: $TAG"
