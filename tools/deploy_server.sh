#!/bin/bash
# xiezhi server 部署（ECS 生产验证环境固化流程，含踩坑教训）：
#   本地交叉编译 → /tmp 中转 mv 原子换（运行中二进制 scp 直写会 Failure）
#   → pkill 独立成步（复合命令 255 断连）→ 起 → 日志断言 → healthz
#   → agent 存活断言（M 批）
# 用法：tools/deploy_server.sh <user@host>（必填）
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -z "${1:-}" ]; then echo "usage: deploy_server.sh user@host"; exit 1; fi
HOST="$1"
REMOTE_DIR=/data/xiezhi

echo "== 1/7 编译 linux/amd64 =="
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/xiezhi-server-deploy ./server/cmd/xiezhi-server

echo "== 2/7 上传 /tmp 中转 =="
scp -q /tmp/xiezhi-server-deploy "$HOST:/tmp/xiezhi-server.new"

echo "== 3/7 停旧进程（独立 ssh，防 pkill 复合命令 255）=="
ssh "$HOST" 'pkill -f "bin/xiezhi-server"' 2>/dev/null || true
sleep 2

echo "== 4/7 原子替换 + 启动 =="
# 启动行必须 setsid + 子 shell 全脱钩：nohup 裸用会让 ssh 会话等继承的
# fd 关闭而挂住（实测 600s 不退）。
# M 批：mv 覆盖前把上一版二进制 cp 成 .prev，留回滚工件（首部署无旧
# 二进制时跳过备份，不挡部署）。
ssh "$HOST" "if [ -f $REMOTE_DIR/bin/xiezhi-server ]; then cp -f $REMOTE_DIR/bin/xiezhi-server $REMOTE_DIR/bin/xiezhi-server.prev; fi && mv /tmp/xiezhi-server.new $REMOTE_DIR/bin/xiezhi-server && chmod 755 $REMOTE_DIR/bin/xiezhi-server && (setsid $REMOTE_DIR/run/start-server.sh </dev/null >/dev/null 2>&1 &) && sleep 4 && echo started"

echo "== 5/7 日志断言（启动关键指标，失败大声）=="
ssh "$HOST" "tail -20 $REMOTE_DIR/run/server.log" > /tmp/deploy-tail.txt
# M-2：断言收紧——rules= 后必须至少一位数字（防 rules=0 空转绿灯）；
# 签名断言只在 REQUIRE_SIGNATURE=1 时强制（dev 无 manifest 时该行不打，
# 旧断言在 dev 下靠 rules 行尾的成功日志误通过）。
for pat in 'rules=[1-9][0-9]* rejected=0' 'mtls=true' 'pg=true'; do
  if ! grep -qE "$pat" /tmp/deploy-tail.txt; then
    echo "FATAL: 启动日志缺关键断言 [$pat]，末尾 20 行："; cat /tmp/deploy-tail.txt; exit 1
  fi
done
echo "日志断言过：rules rejected=0 / manifest verified / mtls / pg"

echo "== 6/7 healthz =="
code=$(ssh "$HOST" 'curl -s --noproxy "*" -o /dev/null -w "%{http_code}" http://127.0.0.1:10581/healthz')
[ "$code" = "200" ] || { echo "FATAL: healthz http $code"; exit 1; }

echo "== 7/7 agent 存活断言（online>=1，失败大声）=="
# /api/agents 与 /alerts 同鉴权面：console auth 开启时匿名 401，须先
# POST /api/auth/login 拿 session cookie 再查（流程同 benchmark/evaluate.sh）。
# 密码取本地 XIEZHI_CONSOLE_PASSWORD，仅经 ssh 通道送远端，curl 走 127.0.0.1。
# agent 心跳默认 60s、online 判定窗 90s——重启后首跳可能未到，重试约 80s。
AGENTS_JSON=""
for i in 1 2 3 4 5; do
  if AGENTS_JSON="$(ssh "$HOST" "CONSOLE_PW='${XIEZHI_CONSOLE_PASSWORD:-}' bash -s" <<'REMOTE'
url=http://127.0.0.1:10581/api/agents
rsp="$(curl -s --noproxy '*' -w '\n%{http_code}' "$url")"
code="${rsp##*$'\n'}"
if [ "$code" = 401 ] && [ -n "$CONSOLE_PW" ]; then
  jar="$(mktemp)"
  lcode="$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -c "$jar" \
    -X POST -H "X-Xiezhi-Password: $CONSOLE_PW" http://127.0.0.1:10581/api/auth/login)"
  if [ "$lcode" = 200 ]; then
    rsp="$(curl -s --noproxy '*' -b "$jar" -w '\n%{http_code}' "$url")"
    code="${rsp##*$'\n'}"
  fi
  rm -f "$jar"
fi
if [ "$code" != 200 ]; then
  echo "FATAL: GET $url -> http $code（console auth 开启时须设 XIEZHI_CONSOLE_PASSWORD）" >&2
  exit 1
fi
printf '%s' "${rsp%$'\n'*}"
REMOTE
)"; then
    # grep 零匹配时退出 1，pipefail+errexit 会在本赋值处直接杀脚本（重试
    # 循环变死代码、失败无声）——须对 grep 容错，online=0 交给重试与收尾复核。
    online="$(printf '%s' "$AGENTS_JSON" | { grep -o '"online":true' || true; } | wc -l)"
    [ "$online" -ge 1 ] && break
    echo "第 $i 轮：online=0（agent 心跳未到/未回连），20s 后重试"
  else
    echo "FATAL: /api/agents 拉取失败（ssh/curl 非零退出），见上" >&2
    exit 1
  fi
  sleep 20
done
# 同上：grep 容错，零匹配交给下面的 FATAL 大声退出（而非 errexit 静默杀）。
online="$(printf '%s' "$AGENTS_JSON" | { grep -o '"online":true' || true; } | wc -l)"
if [ "$online" -lt 1 ]; then
  echo "FATAL: 无在线 agent（online=0）——server 已起但 agent 未回连，需人工介入。/api/agents 响应："
  printf '%s\n' "$AGENTS_JSON"
  exit 1
fi
echo "agent 存活断言过：online=$online"
echo "deploy OK: $HOST  $(date)"
