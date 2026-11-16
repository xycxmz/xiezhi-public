#!/bin/bash
# xiezhi TLS 证书轮换（R8.5，R6 手工流程脚本化）：CA 不动，重签 server 与
# agent 证书（CN 对齐 xiezhi-server/xiezhi-agent）。跑完需重启 server+agent
# （分步 pkill 防 255 断连，见 CONTINUE-TASK §二）。
# 用法：在 ECS 上 bash rotate_certs.sh [/data/xiezhi]
set -euo pipefail
BASE="${1:-/data/xiezhi}"
CA_CRT="${CA_CRT:-$BASE/../hids-v1/etc/tls/ca.crt}"
CA_KEY="${CA_KEY:-$BASE/../hids-v1/etc/tls/ca.key}"
TLS="$BASE/etc/tls"

[ -f "$CA_CRT" ] || { echo "FATAL: CA cert not found: $CA_CRT"; exit 1; }
[ -f "$CA_KEY" ] || { echo "FATAL: CA key not found: $CA_KEY"; exit 1; }
[ -d /etc/hids-agent ] || { echo "FATAL: /etc/hids-agent 不存在（agent 未部署或路径有误）"; exit 1; }
cd "$TLS"

# 覆盖前备份旧 server/agent 证书与私钥（回滚工件）：.pre-rotate/<时间戳>/
BK="$TLS/.pre-rotate/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BK"
for f in server.crt server.key agent.crt agent.key; do
  [ -f "$f" ] || continue
  cp -p "$f" "$BK/"
done
echo "旧证书已备份: $BK"

openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=xiezhi-server"
openssl x509 -req -in server.csr -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
  -out server.crt -days 825 \
  -extfile <(printf "subjectAltName=DNS:xiezhi-server,IP:127.0.0.1")
openssl req -new -newkey rsa:2048 -nodes -keyout agent.key -out agent.csr -subj "/CN=xiezhi-agent"
openssl x509 -req -in agent.csr -CA "$CA_CRT" -CAkey "$CA_KEY" \
  -out agent.crt -days 825
rm -f server.csr agent.csr
chmod 600 server.key agent.key
cp agent.crt agent.key /etc/hids-agent/ && chmod 600 /etc/hids-agent/agent.*
openssl x509 -in server.crt -noout -subject -enddate
openssl x509 -in agent.crt -noout -subject -enddate
echo "certs rotated. restart required:"
echo "  ssh root@host 'pkill -f \"bin/xiezhi-server\"'   # 独立 ssh 分步"
echo "  ssh root@host '/data/xiezhi/run/start-server.sh'（setsid 后台）"
