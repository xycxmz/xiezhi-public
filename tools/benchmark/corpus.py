#!/usr/bin/env python
# -*- coding: ascii -*-
"""Corpus parser and benchmark evaluator for the xiezhi R4 benchmark.

Runs on the CentOS 7 target VM: python 2.7 only, no third-party modules.
Also executes under python 3 for local testing.

Usage:
    corpus.py --tsv corpus.yaml
        Dump runner input as TSV (group, id, bucket, bin, cmd).

    corpus.py --evaluate corpus.yaml exec.log alerts.json
        Read the runner exec log and the /alerts JSON dump, attribute each
        alert to a case by timestamp window, and print the markdown report
        (R4 benchmark report format) to stdout.

The YAML accepted here is a frozen subset: two top-level list sections
(false_positives, attacks), item fields as "key: value" at fixed indent,
block lists ("- entry"), flow lists ("[a, b]"), and single-quoted strings
with '' escapes. Nothing else. corpus.yaml must stay inside that subset.
"""

from __future__ import print_function

import calendar
import json
import re
import sys
import time


SECTIONS = ("false_positives", "attacks")
FIELDS = ("id", "tactic", "technique", "name", "cmd", "creates_process",
          "mode", "bin", "expected_rules", "intent_tags", "bucket", "expect",
          "severity_hint")
LIST_FIELDS = ("expected_rules", "intent_tags")


class CorpusError(Exception):
    pass


def unquote(raw):
    """Decode a YAML-subset scalar. Single-quoted keeps '' escapes; bare
    tokens pass through; [] is the empty flow list."""
    raw = raw.strip()
    if raw == "[]":
        return []
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [unquote(p) for p in inner.split(",")]
    if len(raw) >= 2 and raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1].replace("''", "'")
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return raw


def parse_corpus(path):
    cases = {"false_positives": [], "attacks": []}
    section = None
    item = None
    pending_list = None
    with open(path, "r") as fh:
        for lineno, line in enumerate(fh, 1):
            stripped = line.rstrip("\n").rstrip("\r")
            if not stripped.strip() or stripped.lstrip().startswith("#"):
                continue
            if not stripped.startswith(" ") and stripped.endswith(":"):
                name = stripped[:-1].strip()
                if name not in SECTIONS:
                    raise CorpusError("line %d: unknown section %r" % (lineno, name))
                section = name
                item = None
                pending_list = None
                continue
            if section is None:
                raise CorpusError("line %d: content before any section" % lineno)
            if stripped.startswith("  - "):
                item = {"group": "fp" if section == "false_positives" else "attack",
                        "bucket": "", "bin": ""}
                cases[section].append(item)
                keyval = stripped[4:]
                pending_list = None
                if keyval.strip():
                    pending_list = _apply(item, keyval, lineno)
                continue
            if item is None:
                raise CorpusError("line %d: field outside item" % lineno)
            indented = stripped.startswith("      - ")
            if pending_list is not None and indented:
                item[pending_list].append(unquote(stripped.strip()[2:]))
                continue
            if pending_list is not None and stripped.startswith("    ") and not indented:
                pending_list = None
            pending_list = _apply(item, stripped.strip(), lineno)
    for group in cases.values():
        for c in group:
            for f in LIST_FIELDS:
                if not isinstance(c.get(f), list):
                    c[f] = [c[f]] if c.get(f) else []
    return cases


def _apply(item, keyval, lineno):
    if ":" not in keyval:
        raise CorpusError("line %d: not key: value: %r" % (lineno, keyval))
    key, _, raw = keyval.partition(":")
    key = key.strip()
    if key not in FIELDS:
        raise CorpusError("line %d: unknown field %r" % (lineno, key))
    value = unquote(raw)
    if key in LIST_FIELDS:
        if isinstance(value, list):
            item[key] = value
            return None
        if value == "" or value == []:
            item[key] = []
            return key
        item[key] = [value]
        return None
    item[key] = value
    return None


# ---------------------------------------------------------------- TSV dump

def dump_tsv(path):
    cases = parse_corpus(path)
    out = []
    for c in cases["false_positives"] + cases["attacks"]:
        bucket = c.get("bucket", "") or "-"
        group = bucket if bucket != "-" else c["group"]
        # "-" placeholders: bash "IFS=$'\\t' read" collapses adjacent tabs,
        # so empty fields must never be emitted as empty columns.
        out.append("\t".join([group, c["id"], bucket,
                              c.get("bin", "") or "-", c["cmd"]]))
    return "\n".join(out) + "\n"


# ------------------------------------------------------------- evaluation

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
GRACE_MS = 3500  # alert pipeline latency: intent poll 1s + batch flush 1s


def parse_exec_log(path):
    header = {}
    rows = []
    with open(path, "r") as fh:
        for line in fh:
            line = line.rstrip("\n").rstrip("\r")
            if not line:
                continue
            if line.startswith("#"):
                for tok in line.split():
                    if "=" in tok and not tok.startswith("#"):
                        k, _, v = tok.partition("=")
                        header[k] = v
                continue
            parts = line.split("\t")
            if len(parts) < 7:
                continue
            # Old runner logs wrote ns (and briefly us) timestamps; the header
            # line and current runner write ms. Normalize by magnitude so
            # evaluate accepts all three (1.7e12 ms / 1.7e15 us / 1.7e18 ns).
            def _ms(v):
                v = int(v)
                if v > 10 ** 17:
                    v //= 10 ** 6
                elif v > 10 ** 15:
                    v //= 10 ** 3
                return v
            rows.append({"start_ms": _ms(parts[0]), "end_ms": _ms(parts[1]),
                         "id": parts[2], "group": parts[3],
                         "uid": parts[4], "bin_found": parts[5],
                         "rc": parts[6], "cmd": parts[7] if len(parts) > 7 else ""})
    rows.sort(key=lambda r: r["start_ms"])
    return header, rows


def alert_epoch_seconds(ts):
    """Alert ts comes from ClickHouse DateTime via Go json: RFC3339 with
    offset, or a naive 'YYYY-MM-DD HH:MM:SS' in server-local time. Naive
    values are interpreted in the local timezone of wherever this script
    runs (run evaluate on the VM or same-TZ host)."""
    ts = str(ts).strip()
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})"
                 r"(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$", ts)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    st = time.struct_time((y, mo, d, h, mi, s, 0, 0, -1))
    off = m.group(8)
    if off in (None, ""):
        return time.mktime(st)
    if off == "Z":
        offset = 0
    else:
        sign = 1 if off[0] == "+" else -1
        digits = off[1:].replace(":", "")
        offset = sign * (int(digits[:2]) * 3600 + int(digits[2:]) * 60)
    return calendar.timegm(st) - offset


def evaluate(corpus_path, log_path, alerts_path):
    cases = parse_corpus(corpus_path)
    all_cases = cases["false_positives"] + cases["attacks"]
    by_id = {}
    for c in all_cases:
        by_id[c["id"]] = c
    header, rows = parse_exec_log(log_path)
    if not rows:
        raise CorpusError("exec log %s has no case rows" % log_path)
    with open(alerts_path, "r") as fh:
        alerts = json.load(fh)
    for i, row in enumerate(rows):
        row["case"] = by_id.get(row["id"])
        row["window_end_ms"] = rows[i + 1]["start_ms"] + GRACE_MS if i + 1 < len(rows) \
            else row["end_ms"] + GRACE_MS

    run_start_ms = rows[0]["start_ms"]
    run_end_ms = rows[-1]["window_end_ms"]

    attributed = []   # (alert, row)
    stray = []
    for a in alerts:
        ts = alert_epoch_seconds(a.get("ts", ""))
        if ts is None:
            stray.append((a, "unparseable ts"))
            continue
        ts_ms = int(ts * 1000)
        a["_ts_ms"] = ts_ms
        if ts_ms < run_start_ms - 60000 or ts_ms > run_end_ms + 60000:
            stray.append((a, "outside run window (pre-existing noise)"))
            continue
        covering = [row for row in rows
                    if row["start_ms"] - 500 <= ts_ms <= row["window_end_ms"]]
        inprog = None
        for row in covering:
            if row["start_ms"] <= ts_ms:
                inprog = row
        holder = None
        # In-progress case claims its own alerts first; the grace window only
        # rescues alerts whose pipeline latency spilled them into the next
        # case's window (scan newest-first so a late alert returns to the
        # case that expects its rule).
        for row in reversed(covering):
            if row["case"] and a["rule_id"] in row["case"]["expected_rules"]:
                holder = row
                break
        if holder is None:
            holder = inprog if inprog is not None else (covering[0] if covering else None)
        if holder is None:
            stray.append((a, "before first case"))
        else:
            attributed.append((a, holder))

    for a, row in attributed:
        row.setdefault("observed", []).append(a)
    for row in rows:
        row["observed"] = row.get("observed", [])

    return header, rows, attributed, stray


def is_truthy(v):
    return v in ("true", "True", True, 1)


def is_hit(verdict):
    return verdict == "HIT" or verdict.startswith("PARTIAL")


def fmt_rules(case):
    return ", ".join(case["expected_rules"]) if case["expected_rules"] else "-"


def observed_kinds(row):
    seen = []
    for a in row.get("observed", []):
        if a["rule_id"] not in seen:
            seen.append(a["rule_id"])
    return seen


def build_report(corpus_path, log_path, alerts_path):
    header, rows, attributed, stray = evaluate(corpus_path, log_path, alerts_path)

    fp_rows = [r for r in rows if r["case"] and r["case"]["group"] == "fp"]
    attack_rows = [r for r in rows if r["case"] and r["case"]["group"] == "attack"]

    out = []
    w = out.append
    w("# xiezhi R4 Benchmark Results")
    w("")
    w("- corpus: `%s`" % corpus_path)
    w("- exec log: `%s`" % log_path)
    if header.get("start"):
        w("- run start epoch ms: %s  host: %s  isolate: %s  sleep: %s"
          % (header.get("start"), header.get("host", "?"),
             header.get("isolate", "?"), header.get("sleep", "?")))
    w("- alerts analyzed: %d attributed, %d stray"
      % (len(attributed), len(stray)))

    # ------------------------------------------------ detection matrix
    w("")
    w("## Detection matrix (attack cases)")
    w("")
    w("| ID | Tactic | Tech | Mode | Command | Expected rules | Observed | Verdict |")
    w("|---|---|---|---|---|---|---|---|")
    verdicts = {}
    for row in attack_rows:
        c = row["case"]
        exp = c["expected_rules"]
        obs = observed_kinds(row)
        obs_real = [r for r in obs if not r.startswith("firstseen/")]
        hit = [r for r in exp if r in obs_real]
        if c["expect"] == "gap":
            verdict = "UNEXPECTED-HIT" if obs_real else "gap (no rule)"
        elif exp:
            if len(hit) == len(exp) and exp:
                verdict = "HIT"
            elif hit:
                verdict = "PARTIAL (%d/%d)" % (len(hit), len(exp))
            else:
                verdict = "MISS"
        else:
            verdict = "?"
        verdicts[c["id"]] = verdict
        cmd = c["cmd"] if len(c["cmd"]) <= 60 else c["cmd"][:57] + "..."
        bucket = c.get("bucket", "")
        cid = c["id"] + (" *" + bucket if bucket else "")
        w("| %s | %s | %s | %s | `%s` | %s | %s | %s |"
          % (cid, c["tactic"], c["technique"], c["mode"], cmd,
             fmt_rules(c), ", ".join(obs_real) if obs_real else "-", verdict))

    # -------------------------------------------------- false positives
    w("")
    w("## False-positive group (normal ops, must stay below high)")
    w("")
    w("| ID | Command | Observed alerts | Verdict |")
    w("|---|---|---|---|")
    fp_high = 0
    fp_borderline = 0
    for row in fp_rows:
        c = row["case"]
        obs = observed_kinds(row)
        sevs = []
        for a in row.get("observed", []):
            if a["rule_id"] not in sevs:
                sevs.append("%s(%s)" % (a["rule_id"], a["severity"]))
        highish = [a for a in row.get("observed", [])
                   if SEV_ORDER.get(a["severity"], 0) >= SEV_ORDER["high"]]
        if highish:
            fp_high += len(highish)
            verdict = "FALSE POSITIVE"
        elif sevs:
            fp_borderline += 1
            verdict = "noise (below high)"
        else:
            verdict = "clean"
        cmd = c["cmd"] if len(c["cmd"]) <= 60 else c["cmd"][:57] + "..."
        w("| %s | `%s` | %s | %s |" % (c["id"], cmd,
                                       ", ".join(sevs) if sevs else "-", verdict))
    w("")
    w("**False positives (high+ alerts during benign ops): %d** (+%d borderline cases)"
      % (fp_high, fp_borderline))

    # ------------------------------------------------------------ chains
    w("")
    w("## Kill-chain accumulation (shared intent buckets)")
    w("")
    w("| Chain | Case | Expected | Observed | Verdict |")
    w("|---|---|---|---|---|")
    chains = {}
    for row in attack_rows:
        c = row["case"]
        if c.get("bucket"):
            chains.setdefault(c["bucket"], []).append(row)
    for name in sorted(chains):
        for row in chains[name]:
            c = row["case"]
            obs = [r for r in observed_kinds(row) if not r.startswith("firstseen/")]
            hit = [r for r in c["expected_rules"] if r in obs]
            if c["expect"] == "gap":
                verdict = "gap (no rule)" if not obs else "UNEXPECTED-HIT"
            elif hit and len(hit) == len(c["expected_rules"]):
                verdict = "HIT"
            elif hit:
                verdict = "PARTIAL"
            else:
                verdict = "MISS"
            w("| %s | %s | %s | %s | %s |"
              % (name, c["id"], fmt_rules(c), ", ".join(obs) or "-", verdict))

    # --------------------------------------------------------- statistics
    w("")
    w("## Statistics")
    w("")
    det = [c for c in (r["case"] for r in attack_rows) if c["expect"] == "detectable"]
    det_hit = [c for c in det if is_hit(verdicts.get(c["id"], ""))]
    det_strict = [c for c in det if verdicts.get(c["id"]) == "HIT"]
    real_rows = [r for r in attack_rows if is_truthy(r["case"]["creates_process"])]
    real_det_rows = [r for r in real_rows if r["case"]["expect"] == "detectable"]
    real_det = [r for r in real_det_rows if is_hit(verdicts.get(r["case"]["id"], ""))]
    w("- attack cases: %d isolated+chain (of which creates_process=true: %d)"
      % (len(attack_rows), len(real_rows)))
    w("- benign cases: %d" % len(fp_rows))
    w("- detection rate (at least one expected rule): **%d/%d = %.0f%%** of detectable cases"
      % (len(det_hit), len(det),
         100.0 * len(det_hit) / len(det) if det else 0.0))
    w("- detection rate (all expected rules, strict): %d/%d = %.0f%%"
      % (len(det_strict), len(det),
         100.0 * len(det_strict) / len(det) if det else 0.0))
    w("- detection rate over creates_process=true subset: %d/%d = %.0f%%"
      % (len(real_det), len(real_rows),
         100.0 * len(real_det) / len(real_rows) if real_rows else 0.0))
    w("  (of which %d are detectable cases, %d detected = %.0f%%; the rest are"
      % (len(real_det_rows), len(real_det),
         100.0 * len(real_det) / len(real_det_rows) if real_det_rows else 0.0))
    w("   corpus-declared coverage gaps with no rule to hit)")
    w("- false-positive rate (benign ops triggering high+): **%d/%d = %.0f%%**"
      % (fp_high, len(fp_rows),
         100.0 * fp_high / len(fp_rows) if fp_rows else 0.0))

    tactics = {}
    for row in attack_rows:
        c = row["case"]
        t = tactics.setdefault(c["tactic"], {"n": 0, "det": 0, "detset": 0})
        t["n"] += 1
        if c["expect"] == "detectable":
            t["detset"] += 1
            if is_hit(verdicts.get(c["id"], "")):
                t["det"] += 1
    w("")
    w("| Tactic | Cases | Detectable | Detected |")
    w("|---|---|---|---|")
    for name in sorted(tactics):
        t = tactics[name]
        w("| %s | %d | %d | %d |" % (name, t["n"], t["detset"], t["det"]))

    sev_count = {}
    for a, _ in attributed:
        sev_count[a["severity"]] = sev_count.get(a["severity"], 0) + 1
    w("")
    w("Alert severity distribution (attributed): " +
      ", ".join("%s=%d" % (k, sev_count[k]) for k in sorted(sev_count, key=lambda s: -SEV_ORDER.get(s, 0)))
      if sev_count else "Alert severity distribution: none")

    if stray:
        w("")
        w("## Stray alerts (excluded from scoring)")
        w("")
        for a, why in stray[:20]:
            w("- %s %s %s: %s" % (a.get("ts"), a.get("severity"),
                                  a.get("rule_id"), why))
    w("")
    w("## Reading notes")
    w("")
    w("- Seed rules match per argv element; multi-token patterns are only")
    w("  visible when the full command string rides one argv element, which")
    w("  the runner guarantees via `bash -c`. Interactive-shell execution of")
    w("  the same commands is invisible to kernel execve hooks (known")
    w("  boundary; creates_process=false group).")
    w("- Intent layer alerts once per (host, uid) bucket per 10-minute")
    w("  window. Isolated cases run under per-case uids, so intent/<tag>")
    w("  expectations appear only where a single event scores >= 8.0")
    w("  (mining 9.0, reverse_shell 8.0, authorized_keys write 10.0) or in")
    w("  chain buckets. Tags below threshold are reported as intent_tags,")
    w("  not misses.")
    w("- GAP rows are coverage holes in the current seed rules + intent")
    w("  policy, kept in the corpus to track them, not engine failures.")
    return "\n".join(out) + "\n"


def main(argv):
    if len(argv) == 3 and argv[1] == "--tsv":
        sys.stdout.write(dump_tsv(argv[2]))
        return 0
    if len(argv) == 5 and argv[1] == "--evaluate":
        sys.stdout.write(build_report(argv[2], argv[3], argv[4]))
        return 0
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
