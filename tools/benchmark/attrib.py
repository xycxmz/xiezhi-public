#!/usr/bin/env python3
# One-shot R5 benchmark attribution: tolerant window (+-20s) matching of each
# case's expected rules against real alerts. The replay harness already proved
# exact rule->case mapping; this absorbs CH DateTime second-truncation skew.
import json, re, sys
from datetime import datetime, timedelta

CORPUS = "/data/xiezhi/tools/benchmark/corpus.yaml"
LOG = "/tmp/benchmark-exec.log"
ALERTS = "/tmp/benchmark-alerts.json"
TOL_MS = 20_000

# -- parse corpus (frozen subset) --
cases, cur, pend = [], None, None
section = ""
for raw in open(CORPUS, encoding="utf-8"):
    line = raw.rstrip("\r\n")
    tr = line.strip()
    if not tr or tr.startswith("#"):
        continue
    if not line.startswith(" ") and line.endswith(":"):
        section = tr[:-1]; cur = None; pend = None; continue
    if line.startswith("  - "):
        cur = {"group": section, "expected": []}
        cases.append(cur)
        pend = None
        rest = tr[2:].strip()
        if rest.startswith("-"): rest = rest[1:].strip()
        if rest:
            k, _, v = rest.partition(":")
            k = k.strip(); v = v.strip()
            if k == "id": cur["id"] = v
        continue
    if cur is None:
        continue
    if pend == "expected_rules" and line.startswith("      - "):
        cur["expected"].append(tr[2:]); continue
    k, _, v = tr.partition(":")
    k = k.strip(); v = v.strip()
    pend = None
    if k == "id": cur["id"] = v
    elif k == "cmd": cur["cmd"] = v.strip("'")
    elif k == "expect": cur["expect"] = v
    elif k == "expected_rules":
        if v in ("", "[]"): pend = "expected_rules"
        else: cur["expected"] = [v.strip("'")]

# -- parse exec log (ns normalizing) --
rows = []
for line in open(LOG):
    if line.startswith("#"):
        continue
    p = line.rstrip("\n").split("\t")
    if len(p) < 7:
        continue
    def ms(v):
        v = int(v)
        return v // 10**6 if v > 10**17 else (v // 10**3 if v > 10**15 else v)
    rows.append({"start": ms(p[0]), "end": ms(p[1]), "id": p[2], "group": p[3]})
by_id = {r["id"]: r for r in rows}

# -- alerts --
data = json.load(open(ALERTS))
alerts = data if isinstance(data, list) else data.get("alerts", data.get("items", []))
def ts_ms(a):
    s = str(a.get("ts", ""))
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})"
                 r"(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$", s.strip())
    if not m:
        return None
    import calendar
    y, mo, d, h, mi, sec = (int(m.group(i)) for i in range(1, 7))
    try:
        base = calendar.timegm((y, mo, d, h, mi, sec, 0, 0, 0))  # naive as UTC
    except Exception:
        return None
    off = m.group(8)
    if off and off != "Z":
        sign = 1 if off[0] == "+" else -1
        digits = off[1:].replace(":", "")
        base -= sign * (int(digits[:2]) * 3600 + int(digits[2:]) * 60)
    ms_frac = m.group(7)
    frac = int(ms_frac[:3].ljust(3, "0")) if ms_frac else 0
    return base * 1000 + frac
run_lo = min(r["start"] for r in rows) - 60_000
run_hi = max(r["end"] for r in rows) + 60_000
prepped = []
skipped_old = 0
for a in alerts:
    t = ts_ms(a)
    if t is None:
        continue
    if t < run_lo or t > run_hi:
        skipped_old += 1
        continue
    prepped.append((t, a.get("rule_id", "?"), a.get("severity", "")))
print("alerts in run window: %d (skipped %d pre-run/post-run)" % (len(prepped), skipped_old))

# -- attribute --
detected = miss_cnt = fp_hits = 0
misses = []
results = []
for c in cases:
    row = by_id.get(c["id"])
    if not row:
        continue
    lo, hi = row["start"] - TOL_MS, row["end"] + TOL_MS
    near = {(r, s) for (t, r, s) in prepped if lo <= t <= hi}
    if c["group"] == "false_positives":
        high = [r for (r, s) in near if s in ("high", "critical")]
        if high:
            fp_hits += 1
            results.append((c["id"], "FP-HIGH: " + ",".join(sorted(set(high)))))
        continue
    if not c.get("expected"):
        continue  # gap-by-design cases: skip in scoring, report separately
    got = {r for (r, s) in near}
    missing = [r for r in c["expected"] if r not in got]
    if missing:
        miss_cnt += 1
        misses.append((c["id"], missing))
    else:
        detected += 1

gap_no_rule = [c["id"] for c in cases if c.get("expect") == "gap"]
scored = detected + miss_cnt
print("scored cases:", scored, "detected:", detected,
      "rate: %.0f%%" % (100.0 * detected / scored) if scored else "n/a")
print("false-positive cases with high+ alerts:", fp_hits)
print("miss list:")
for cid, miss in misses:
    print(" ", cid, miss)
print("gap-by-design (unscored):", gap_no_rule)
