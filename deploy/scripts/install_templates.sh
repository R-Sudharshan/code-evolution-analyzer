#!/usr/bin/env bash
# Download ONLY the safe, low-impact official Nuclei template subsets into a
# controlled docker volume (no full collection, no auto-update at runtime).
set -euo pipefail
cd "$(dirname "$0")/.."

TEMPLATE_TAG=${TEMPLATE_TAG:-v10.2.9}
VOLUME=${VOLUME:-pentai-nuclei-templates}
WORK=$(mktemp -d)
export WORK

cleanup() { rm -rf "$WORK"; docker rm -f pentai-tpl-installer >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[*] Downloading official nuclei-templates ${TEMPLATE_TAG} (selected subsets)"
git clone --depth 1 --branch "$TEMPLATE_TAG" \
  https://github.com/projectdiscovery/nuclei-templates "$WORK/tpl"

KEEP="misconfiguration exposures technologies"
mkdir -p "$WORK/out/http"
for k in $KEEP; do
  if [ -d "$WORK/tpl/http/$k" ]; then
    cp -r "$WORK/tpl/http/$k" "$WORK/out/http/"
  else
    echo "[-] missing subset http/$k (tag drift? pick another TEMPLATE_TAG)"; exit 1
  fi
done

WORK="$WORK" python3 - <<'EOF'
import os, re, pathlib
root = pathlib.Path(os.environ["WORK"], "out")
n = 0
for f in root.rglob("*.yaml"):
    t = f.read_text(errors="ignore")
    if re.search(r'^\s*(unsafe:\s*true|code:\s*true|interactsh_required:\s*true)', t, re.M):
        f.unlink(); n += 1
print(f"[i] removed {n} unsafe/code/interactsh templates")
EOF

echo "[*] Populating docker volume $VOLUME"
docker volume create "$VOLUME" >/dev/null
docker run -d --rm --name pentai-tpl-installer -v "$VOLUME:/vol" alpine:3.21 sleep 120 >/dev/null
sleep 1
echo "$TEMPLATE_TAG" > "$WORK/out/.template-version"
docker cp "$WORK/out/." pentai-tpl-installer:/vol/
docker rm -f pentai-tpl-installer >/dev/null

echo "[*] Verifying volume contents"
docker run --rm -v "$VOLUME:/vol:ro" alpine:3.21 sh -c 'cat /vol/.template-version; ls /vol/http; find /vol/http -name "*.yaml" | wc -l'
echo "[+] Templates installed (pinned $TEMPLATE_TAG). Runtime auto-update disabled (-duc)."
