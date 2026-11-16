#!/bin/bash
# R3.5: Generate ed25519 signing key pair for rules/config signing.
# Usage: tools/gen_signing_key.sh [--force] <output-dir>
# Produces: signing-key (private, 600) + signing-key.pub (public)
# --force: 输出已存在时强制覆盖（默认拒绝——防误换现网验签私钥）
set -euo pipefail
FORCE=0
if [ "${1:-}" = "--force" ]; then FORCE=1; shift; fi
OUT="${1:?usage: gen_signing_key.sh [--force] <outdir>}"
if [ "$FORCE" -eq 0 ] && { [ -e "$OUT/signing-key" ] || [ -e "$OUT/signing-key.pub" ]; }; then
  echo "FATAL: $OUT/signing-key(.pub) 已存在，拒绝覆盖；确认重签请加 --force" >&2
  exit 1
fi
mkdir -p "$OUT"
openssl genpkey -algorithm ed25519 -out "$OUT/signing-key"
openssl pkey -in "$OUT/signing-key" -pubout -out "$OUT/signing-key.pub"
chmod 600 "$OUT/signing-key"
chmod 644 "$OUT/signing-key.pub"
echo "ed25519 key pair ready: $OUT/signing-key (private) + $OUT/signing-key.pub (public)"
