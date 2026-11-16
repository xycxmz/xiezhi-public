#!/bin/bash
# xiezhi R4 benchmark runner. Executes every corpus case on the target VM
# (CentOS 7, LKM driver loaded, agent connected) and writes the exec log
# that evaluate.sh turns into the detection matrix.
#
# Usage:  ./runner.sh [corpus.yaml]
#
# Env:
#   BENCH_EXEC_LOG  default /tmp/benchmark-exec.log
#   BENCH_SLEEP     seconds between cases, default 2. The 1s spec floor is
#                   honored via BENCH_SLEEP=1, but 2 keeps per-case alert
#                   attribution clean (alert timestamps have 1s granularity,
#                   the intent layer polls at 1s and flushes batches at 1s)
#                   and leaves headroom under the 10 alerts/min/rule engine
#                   rate limiter.
#   BENCH_ISOLATE   default 1: each case runs under its own throwaway uid
#                   (setpriv), so legacy-mode intent buckets (host, uid) stay
#                   per-case and chain groups get one shared uid each.
#                   0 = run everything as root (R2-compat smoke mode):
#                   intent expectations then only measure the first bucket
#                   crossing, and permission-guarded writes (crontab,
#                   sudoers, authorized_keys) REALLY land on the VM.
#   BENCH_TIMEOUT   per-case timeout seconds, default 10.
#   BENCH_SSH_KEY   session-tree isolation: each case runs in its own ssh
#                   localhost session (independent FORK tree), because root
#                   bucket keys (host, rootPid) co-bucket every case that
#                   shares the runner's tree (measured: 3-round run at 88%
#                   with all intent cases co-suppressed). setsid does NOT
#                   help - the FORK edge is recorded at fork time and
#                   reparenting never removes it. Unset/unreachable = loud
#                   fallback to the runner tree with degraded isolation.
#
# Every case runs as: timeout N setpriv --reuid=UID bash -c "<cmd>"
# The full command string therefore lands in one argv element, which is the
# only argv shape the per-element regex rules and intent labeler can match
# for multi-token patterns. Missing binaries fail after execve with
# "command not found", which is still a fully detectable event and has no
# side effect. Commands whose binaries do exist only touch /tmp/bench-*
# targets or fail on permission under isolation.

set -u

DIR=$(cd "$(dirname "$0")" && pwd)
CORPUS=${1:-$DIR/corpus.yaml}
LOG=${BENCH_EXEC_LOG:-/tmp/benchmark-exec.log}
SLEEP=${BENCH_SLEEP:-2}
ISOLATE=${BENCH_ISOLATE:-1}
TMO=${BENCH_TIMEOUT:-10}

# corpus.py runs on both CentOS 7 (python2.7) and the Ubuntu ECS (python3).
if command -v python2 >/dev/null 2>&1; then
  PY=python2
elif command -v python3 >/dev/null 2>&1; then
  PY=python3
else
  PY=python
fi

if [ ! -r "$CORPUS" ]; then
  echo "ERROR: corpus not readable: $CORPUS" >&2
  exit 1
fi

if ! "$PY" "$DIR/corpus.py" --tsv "$CORPUS" >/dev/null; then
  echo "ERROR: corpus parse failed" >&2
  exit 1
fi

if [ "$ISOLATE" = "1" ] && ! command -v setpriv >/dev/null 2>&1; then
  echo "WARNING: setpriv missing, falling back to root (no bucket isolation)" >&2
  ISOLATE=0
fi
if [ "$ISOLATE" = "0" ]; then
  echo "WARNING: BENCH_ISOLATE=0 smoke mode - cases run as root; guarded" 2>&1
  echo "         writes (cron/sudoers/authorized_keys) really happen" 2>&1
fi

# 会话树隔离探测：BENCH_SSH_KEY 可用才走每案独立 ssh 会话；否则大声降级
# （root 桶键下全部案子共桶，intent 案评估失效——三轮 88% 的实测教训）。
SSH_WRAP=0
if [ -n "${BENCH_SSH_KEY:-}" ] && \
   ssh -n -o BatchMode=yes -o ConnectTimeout=3 -i "$BENCH_SSH_KEY" root@127.0.0.1 true 2>/dev/null; then
  SSH_WRAP=1
else
  echo "WARNING: BENCH_SSH_KEY unset or unreachable - every case shares the" 2>&1
  echo "         runner session tree; per-case intent buckets are NOT isolated" 2>&1
fi

mkdir -p /tmp/bench-impact-dir
: > /tmp/bench-immutable-test 2>/dev/null || true
rm -f /tmp/bench-dd.img /tmp/bench-stage.tar.gz /tmp/bench-exfil.tar.gz \
      /tmp/bench-conf-list.txt /tmp/bench-pool.conf /tmp/bench-backup.tar.gz \
      /tmp/bench-key /tmp/bench-key.pub /tmp/bench-cap.pcap

: > "$LOG"
printf '# BENCH-R4 start=%s host=%s isolate=%s sleep=%s timeout=%s\n' \
  "$(( $(date +%s%N) / 1000000 ))" "$(hostname)" "$ISOLATE" "$SLEEP" "$TMO" >> "$LOG"

# 每轮 uid 偏移：intent 桶键含 uid 且窗口 10min 内首跨只告一次——静态复用
# 3000+idx 会让紧邻两轮 benchmark 的同 uid 桶互相抑制（第二轮逐案 intent
# 全静默）。偏移按 epoch 分钟轮转，相邻两轮必然错开。
UID_OFFSET=$(( ($(date +%s) / 60 % 40) * 120 ))

uid_for() {
  case "$1" in
    fp)      echo 0 ;;
    chain-A) echo $((5001 + UID_OFFSET)) ;;
    chain-B) echo $((5002 + UID_OFFSET)) ;;
    chain-C) echo $((5003 + UID_OFFSET)) ;;
    *)       echo $((3000 + UID_OFFSET + $2)) ;;
  esac
}

seq_no=0
while IFS=$'\t' read -r grp cid bucket bin cmd; do
  [ -n "$cid" ] || continue
  seq_no=$((seq_no + 1))
  uid=$(uid_for "$grp" "$seq_no")
  if [ "$bin" != "-" ] && [ -n "$bin" ] && command -v "$bin" >/dev/null 2>&1; then
    found=1
  else
    found=0
  fi
  start=$(( $(date +%s%N) / 1000000 ))
  # 会话树隔离优先走 ssh：每案独立 ssh 会话=独立 FORK 树，root 桶键按案分桶。
  # ssh 退出码透传（255=ssh 自身失败，与 corpus rc 语义区分见头部注释）。
  if [ "$SSH_WRAP" = "1" ]; then
    # bash -c 包装必须保留：sim-missing-bin 案（corpus 一半）的检测依赖
    # 包装层 argv 含命令全文——sched_process_exec 只在成功后触发，stdin
    # 传法（bash -s）会让不存在的命令零事件（七轮 24% 实测）。代价是
    # 同一动作最多三层 argv 计数（本地 ssh/远端包装/实际 exec），benign
    # scp 单案可凑 9.0——记为已知产品项（跨机不双计，真实危害限同机
    # localhost 形态），收敛归 intent 分值调参轮。
    qcmd=$(printf '%q' "$cmd")
    if [ "$ISOLATE" = "1" ] && [ "$uid" != "0" ]; then
      ssh -n -o BatchMode=yes -o ConnectTimeout=5 -i "$BENCH_SSH_KEY" root@127.0.0.1 \
        "timeout $TMO setpriv --reuid=$uid --regid=$uid --clear-groups bash -c $qcmd" \
        >/dev/null 2>&1
    else
      ssh -n -o BatchMode=yes -o ConnectTimeout=5 -i "$BENCH_SSH_KEY" root@127.0.0.1 \
        "timeout $TMO bash -c $qcmd" >/dev/null 2>&1
    fi
    rc=$?
  elif [ "$ISOLATE" = "1" ] && [ "$uid" != "0" ]; then
    timeout "$TMO" setpriv --reuid="$uid" --regid="$uid" --clear-groups \
      bash -c "$cmd" >/dev/null 2>&1
    rc=$?
  else
    timeout "$TMO" bash -c "$cmd" >/dev/null 2>&1
    rc=$?
  fi
  end=$(( $(date +%s%N) / 1000000 ))
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$start" "$end" "$cid" "$grp" "$uid" "$found" "$rc" "$cmd" >> "$LOG"
  echo "[$cid] group=$grp uid=$uid bin_found=$found rc=$rc"
  sleep "$SLEEP"
done < <("$PY" "$DIR/corpus.py" --tsv "$CORPUS")

total=$seq_no
echo ""
echo "Executed $total cases. Waiting 5s for the detection chain to digest..."
sleep 5
echo "DONE. exec log: $LOG"
echo "Next: ./evaluate.sh $CORPUS $LOG"
