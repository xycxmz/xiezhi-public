#!/usr/bin/env python3
"""紧窗 FP 复核（纪律：attrib.py 宽窗 20s 会渗邻案，FP 判定用 ±2.5s）。

用法：python3 fpcheck_tight.py [exec_log] [alerts_json]
默认 /tmp/benchmark-exec.log /tmp/benchmark-alerts.json（evaluate.sh 的产物）。
合格线：15 条误报用例紧窗内零 high+ 告警。
"""
import datetime
import json
import sys

EXEC_LOG = sys.argv[1] if len(sys.argv) > 1 else "/tmp/benchmark-exec.log"
ALERTS = sys.argv[2] if len(sys.argv) > 2 else "/tmp/benchmark-alerts.json"
TOL_MS = 2500
HIGH_PLUS = ("high", "critical")


def pms(s: str) -> int:
    return int(
        datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000
    )


def main() -> None:
    rows = [l.split("\t") for l in open(EXEC_LOG, encoding="utf-8") if l.strip()]
    alerts = json.load(open(ALERTS, encoding="utf-8"))
    viol = 0
    for row in rows:
        if len(row) < 8 or row[3] != "fp":
            continue
        start_ms, end_ms, cid = int(row[0]), int(row[1]), row[2]
        # M-1：窗口为 [start-TOL, end+TOL]——案子自身可运行数秒（TMO=10s），
        # 只锚 start±TOL 会把案中后段触发的 high+ 漏判为 clean（R8.4 审计）。
        hi = [
            a
            for a in alerts
            if start_ms - TOL_MS <= pms(a["ts"]) <= end_ms + TOL_MS
            and a["severity"] in HIGH_PLUS
        ]
        if hi:
            viol += 1
            print(cid, "VIOLATION:", [(a["rule_id"], a["severity"], a["ts"]) for a in hi])
        else:
            print(cid, "clean")
    print(f"tight-window(+/-{TOL_MS}ms) high+ violations: {viol}")
    sys.exit(1 if viol else 0)


if __name__ == "__main__":
    main()
