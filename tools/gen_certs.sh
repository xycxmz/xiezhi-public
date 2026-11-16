#!/bin/bash
# mTLS 证书生成（M2）：一套自签 CA + server 证书 + agent 证书。
# 产物 ca.crt / server.crt+key / agent.crt+key（部署到 etc/tls/，600 权限，不入 git）。
# 用法：tools/gen_certs.sh <输出目录> [SAN，默认 127.0.0.1]
set -euo pipefail
OUT="${1:?usage: gen_certs.sh <outdir> [san]}"
SAN="${2:-127.0.0.1}"
mkdir -p "$OUT"
cd "$OUT"

# EKU：serverAuth+clientAuth 共用一张 agent 证书便于多机分发（轮换走重签）
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt \
  -days 3650 -subj "/CN=xiezhi-ca" >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=xiezhi-server" >/dev/null 2>&1
printf "subjectAltName=DNS:xiezhi-server,IP:%s\nextendedKeyUsage=serverAuth\n" "$SAN" > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -extfile server.ext >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes -keyout agent.key -out agent.csr \
  -subj "/CN=xiezhi-agent" >/dev/null 2>&1
printf "extendedKeyUsage=clientAuth\n" > agent.ext
openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out agent.crt -days 825 -extfile agent.ext >/dev/null 2>&1

rm -f server.csr agent.csr server.ext agent.ext ca.srl
chmod 600 ./*
echo "certs ready in $OUT (ca.crt / server.{crt,key} / agent.{crt,key}, SAN=$SAN)"
