#!/bin/bash
# R3.5: Sign rules directory manifest with ed25519.
# Usage: tools/sign_rules.sh <rules-dir> <signing-key>
# Produces: <rules-dir>/.rules-manifest (JSON) + .rules-signature (binary sig)
set -euo pipefail
DIR="${1:?usage: sign_rules.sh <rules-dir> <signing-key>}"
KEY="${2:?usage: sign_rules.sh <rules-dir> <signing-key>}"

cd "$DIR"
# Build manifest: filename -> sha256 for all .yaml files
MANIFEST=$(ls *.yaml 2>/dev/null | sort | while read f; do
  HASH=$(sha256sum "$f" | cut -d' ' -f1)
  echo "\"$f\":\"$HASH\""
done | paste -sd, - | sed 's/^/{"version":"1","files":{/' | sed 's/$/}}/')

echo "$MANIFEST" > .rules-manifest
# Sign the manifest (raw ed25519, not ASN.1)。-in 文件输入而非管道：Windows
# OpenSSL 3.x 的 pkeyutl -rawin 对 stdin 无法测长（oneslot size 报错）
openssl pkeyutl -sign -inkey "$KEY" -rawin -in .rules-manifest -out .rules-signature
echo "Signed $(ls *.yaml 2>/dev/null | wc -l) rules in $DIR"
echo "Manifest: $(wc -c < .rules-manifest) bytes, signature: $(wc -c < .rules-signature) bytes"
