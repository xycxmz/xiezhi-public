#!/bin/bash
# xiezhi R4 benchmark evaluator. Pulls all alerts from the server /alerts
# API, joins them with the runner exec log, and writes the detection matrix
# (R4 benchmark report format).
#
# Usage:  ./evaluate.sh [corpus.yaml] [exec.log] [output.md]
#         defaults: corpus.yaml and /tmp/benchmark-exec.log next to/under
#         this script, output ./benchmark-r4-results.md (print path hint;
#         keep results out of the repo or gitignore them).
#
# Env:
#   BENCH_SERVER          server base URL, default http://127.0.0.1:10581
#   XIEZHI_CONSOLE_PASSWORD if the server has console auth enabled, the login
#                         password (session cookie flow, max 5 tries then
#                         the server locks the source IP)
#   BENCH_ALERT_LIMIT     /alerts limit, default 1000 (API max; the brief's
#                         500 floor truncates when firstseen digests pile up)

set -u

DIR=$(cd "$(dirname "$0")" && pwd)
CORPUS=${1:-$DIR/corpus.yaml}
LOG=${2:-/tmp/benchmark-exec.log}
OUT=${3:-benchmark-r4-results.md}
BASE=${BENCH_SERVER:-http://127.0.0.1:10581}
LIMIT=${BENCH_ALERT_LIMIT:-1000}
ALERTS_JSON=${BENCH_ALERTS_JSON:-/tmp/benchmark-alerts.json}
COOKIE_JAR=/tmp/bench-cookies.txt

if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python2 >/dev/null 2>&1; then
  PY=python2
else
  PY=python
fi

for f in "$CORPUS" "$LOG"; do
  if [ ! -r "$f" ]; then
    echo "ERROR: not readable: $f (run runner.sh first)" >&2
    exit 1
  fi
done

fetch() {
  curl -sS -m 20 -o "$ALERTS_JSON" -w '%{http_code}' \
    "$BASE/alerts?limit=$LIMIT"
}

code=$(fetch)
if [ "$code" != "200" ]; then
  if [ -n "${XIEZHI_CONSOLE_PASSWORD:-}" ]; then
    lcode=$(curl -sS -m 10 -c "$COOKIE_JAR" -o /dev/null -w '%{http_code}' \
      -X POST -H "X-Xiezhi-Password: $XIEZHI_CONSOLE_PASSWORD" \
      "$BASE/api/auth/login")
    if [ "$lcode" != "200" ]; then
      echo "ERROR: login failed (http $lcode)" >&2
      exit 1
    fi
    code=$(curl -sS -m 20 -b "$COOKIE_JAR" -o "$ALERTS_JSON" -w '%{http_code}' \
      "$BASE/alerts?limit=$LIMIT")
  fi
fi

if [ "$code" != "200" ]; then
  echo "ERROR: GET $BASE/alerts -> http $code (set BENCH_SERVER /" >&2
  echo "       XIEZHI_CONSOLE_PASSWORD if auth is on)" >&2
  exit 1
fi

count=$("$PY" -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' \
  "$ALERTS_JSON" 2>/dev/null || echo "?")
if [ "$count" = "?" ]; then
  echo "ERROR: $ALERTS_JSON is not a JSON array" >&2
  exit 1
fi
echo "Fetched $count alerts from $BASE (limit $LIMIT)"
if [ "$count" = "$LIMIT" ]; then
  echo "WARNING: hit the limit; older alerts may be truncated - consider" >&2
  echo "         raising BENCH_ALERT_LIMIT or clearing old xiezhi.alerts rows" >&2
fi

"$PY" "$DIR/corpus.py" --evaluate "$CORPUS" "$LOG" "$ALERTS_JSON" > "$OUT"
echo "Wrote $OUT"
echo "Report format: R4 benchmark"
