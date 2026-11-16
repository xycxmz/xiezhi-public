#!/bin/bash
# xiezhi 数据备份（R8.5）：CH 关键表 Native dump + PG session/firstseen dump。
# 产物按日期落 ${BACKUP_DIR:-/data/xiezhi/backup}/YYYYmmdd/；建议 cron：
#   0 4 * * * /data/xiezhi/tools/backup.sh >> /data/xiezhi/run/backup.log 2>&1
# 恢复：CH 用 clickhouse-client < file.native（--query 逐表）；PG 用 psql < file.sql。
# ⚠ ECS 上 CH/PG 是 docker 容器（hids-clickhouse / xiezhi-pg），经 docker exec。
set -euo pipefail
DAY=$(date +%Y%m%d)
DIR="${BACKUP_DIR:-/data/xiezhi/backup}/$DAY"
mkdir -p "$DIR"
CH_PW="${XIEZHI_CH_PASSWORD:?need XIEZHI_CH_PASSWORD}"
PG_CONTAINER="${XIEZHI_PG_CONTAINER:-xiezhi-pg}"

echo "== CH alerts/llm_triage（events_raw 量大不进日常备份，按需手加）=="
for t in alerts llm_triage alert_ack; do
  docker exec hids-clickhouse clickhouse-client --password "$CH_PW" \
    -q "SELECT * FROM xiezhi.$t FORMAT Native" | gzip > "$DIR/$t.native.gz"
  echo "  $t $(du -h "$DIR/$t.native.gz" | cut -f1)"
done

echo "== PG session_tree/session_node/first_seen =="
docker exec "$PG_CONTAINER" pg_dump -U postgres -d xiezhi \
  -t session_tree -t session_node -t first_seen | gzip > "$DIR/pg-session.sql.gz"
echo "  pg $(du -h "$DIR/pg-session.sql.gz" | cut -f1)"

# 保留 14 天
find "$(dirname "$DIR")" -maxdepth 1 -type d -name '20*' -mtime +14 -exec rm -rf {} + 2>/dev/null || true
echo "backup done: $DIR"
