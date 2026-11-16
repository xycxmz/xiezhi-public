// SPDX-License-Identifier: Apache-2.0

// r5check: drive the real rules engine over a corpus (benchmark cases or FP
// probes) against a rules directory, in wrapper + direct event shapes. This
// is the deterministic gate for rule work: FP cases must come back clean and
// every expected rule must hit, before anything ships to the ECS.
//
// Usage: go run ./server/tools/r5check <corpus.yaml> <rules-dir>
//
// For every corpus case it feeds two EXECVE events, mirroring runner.sh:
//
//	wrapper: timeout 10 setpriv --reuid=N --regid=N --clear-groups bash -c "<cmd>"
//	direct:  naive whitespace split of cmd (only when creates_process=true)
//
// and attributes every emitted alert back to the case that produced it.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	pb "github.com/xycxmz/xiezhi-public/proto"
	"github.com/xycxmz/xiezhi-public/server/internal/pipeline"
	"github.com/xycxmz/xiezhi-public/server/internal/rules"
)

type caseRow struct {
	group     string // fp | attack
	id        string
	tactic    string
	bucket    string
	bin       string
	cmd       string
	creates   bool
	expected  []string
	wrapHits  []string
	directHit []string
}

type sink struct {
	mu     sync.Mutex
	alerts []*pipeline.Alert
}

func (s *sink) EmitAlert(_ context.Context, a *pipeline.Alert) {
	s.mu.Lock()
	s.alerts = append(s.alerts, a)
	s.mu.Unlock()
}

func (s *sink) Close() {}

func (s *sink) drain() []*pipeline.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.alerts
	s.alerts = nil
	return out
}

// parseCorpus mirrors the frozen corpus.yaml subset (corpus.py): two
// sections, "  - " items, 4-space fields, "      - " block-list entries.
func parseCorpus(path string) ([]*caseRow, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rows []*caseRow
	var cur *caseRow
	pending := ""
	section := ""
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimRight(raw, "\r")
		tr := strings.TrimSpace(line)
		if tr == "" || strings.HasPrefix(tr, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			section = strings.TrimSuffix(tr, ":")
			cur = nil
			pending = ""
			continue
		}
		if strings.HasPrefix(line, "  - ") {
			cur = &caseRow{group: section, expected: nil}
			rows = append(rows, cur)
			pending = ""
			rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line[2:]), "-"))
			if rest != "" {
				applyField(cur, &pending, rest)
			}
			continue
		}
		if cur == nil {
			continue
		}
		if pending != "" && strings.HasPrefix(line, "      - ") {
			cur.expected = append(cur.expected, unq(strings.TrimPrefix(tr, "- ")))
			continue
		}
		applyField(cur, &pending, tr)
	}
	return rows, nil
}

func unq(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && strings.HasPrefix(v, "'") && strings.HasSuffix(v, "'") {
		return strings.ReplaceAll(v[1:len(v)-1], "''", "'")
	}
	return v
}

func applyField(cur *caseRow, pending *string, tr string) {
	key, val, _ := strings.Cut(tr, ":")
	key = strings.TrimSpace(key)
	val = strings.TrimSpace(val)
	*pending = ""
	switch key {
	case "id":
		cur.id = unq(val)
	case "tactic":
		cur.tactic = unq(val)
	case "bucket":
		cur.bucket = unq(val)
	case "bin":
		cur.bin = unq(val)
	case "cmd":
		cur.cmd = unq(val)
	case "creates_process":
		cur.creates = val == "true"
	case "expected_rules":
		if val == "[]" || val == "" {
			cur.expected = []string{}
			*pending = "expected_rules"
		} else {
			cur.expected = []string{unq(val)}
			*pending = ""
		}
	}
}

func wrapperEvent(cmd string) *pb.Event {
	return &pb.Event{
		Header: &pb.EventHeader{AgentId: "r5check", Hostname: "bench", TsMs: 1, EventType: pb.EventType_EXECVE},
		Body: &pb.Event_Execve{Execve: &pb.ExecveEvent{Proc: &pb.ProcessContext{
			Argv: []string{"timeout", "10", "setpriv", "--reuid=5000", "--regid=5000", "--clear-groups", "bash", "-c", cmd},
		}}},
	}
}

func directEvent(cmd string) *pb.Event {
	toks := strings.Fields(cmd)
	for i, t := range toks {
		toks[i] = strings.Trim(t, `"'`)
	}
	if len(toks) == 0 {
		return nil
	}
	return &pb.Event{
		Header: &pb.EventHeader{AgentId: "r5check", Hostname: "bench", TsMs: 1, EventType: pb.EventType_EXECVE},
		Body:   &pb.Event_Execve{Execve: &pb.ExecveEvent{Proc: &pb.ProcessContext{Argv: toks}}},
	}
}

func feed(e *rules.Engine, s *sink, ev *pb.Event) []string {
	before := e.Stats().EventsProcessed
	e.Handle(context.Background(), ev)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if e.Stats().EventsProcessed > before {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	var hits []string
	for _, a := range s.drain() {
		h := a.RuleID + "(" + a.Severity + ")"
		if !contains(hits, h) {
			hits = append(hits, h)
		}
	}
	return hits
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: r5check <corpus.yaml> <rules-dir>")
		os.Exit(2)
	}
	rows, err := parseCorpus(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "corpus:", err)
		os.Exit(1)
	}
	s := &sink{}
	e, err := rules.New(os.Args[2], s, rules.WithAlertRateLimit(1_000_000, time.Minute), rules.WithPollInterval(time.Hour))
	if err != nil {
		fmt.Fprintln(os.Stderr, "engine:", err)
		os.Exit(1)
	}
	defer e.Close()
	st := e.Stats()
	fmt.Printf("load: rules=%d rejected=%d version=%s\n", st.RulesLoaded, st.RulesRejected, st.Version)

	for _, c := range rows {
		c.wrapHits = feed(e, s, wrapperEvent(c.cmd))
		if c.creates {
			if d := directEvent(c.cmd); d != nil {
				c.directHit = feed(e, s, d)
			}
		}
	}

	fpHit := 0
	fmt.Println("\n== false positives (must be empty) ==")
	for _, c := range rows {
		if c.group != "false_positives" {
			continue
		}
		all := append(append([]string{}, c.wrapHits...), c.directHit...)
		// probes 合格线语义（「10 clean + 3 刻意降级命中」）：FP 案的
		// expected_rules 是容许命中白名单——命中白名单内记 ALLOWED，
		// 白名单外才是违规（杂项席 M-3：expected 此前从不被消费）。
		verdict := "clean"
		if extra := diff(stripSev(all), c.expected); len(extra) > 0 {
			verdict = "UNEXPECTED: " + strings.Join(extra, ",")
			fpHit++
		} else if len(all) > 0 {
			verdict = "ALLOWED: " + strings.Join(stripSev(all), ",")
		}
		fmt.Printf("%s %-58s %s\n", c.id, trunc(c.cmd, 58), verdict)
	}

	miss := 0
	fmt.Println("\n== attack cases: gap coverage / unexpected hits ==")
	for _, c := range rows {
		if c.group != "attacks" {
			continue
		}
		all := append(append([]string{}, c.wrapHits...), c.directHit...)
		// 口径：r5check 只起规则引擎且只回放 EXECVE——intent/* 期望属
		// 意图层、conn-* 期望属网络事件面（M06：回放器无 CONNECT 通道，
		// ECS 轮同样覆盖不了，六轮起即 miss），均记 SKIP 不计 MISS。
		// 此前 exit 0 假绿掩盖了口径差。
		expRules := make([]string, 0, len(c.expected))
		for _, e := range c.expected {
			if !strings.HasPrefix(e, "intent/") && !strings.HasPrefix(e, "conn-") {
				expRules = append(expRules, e)
			}
		}
		exp := strings.Join(c.expected, ",")
		obs := strings.Join(stripSev(all), ",")
		var verdict string
		switch {
		case len(c.expected) == 0 && len(all) > 0:
			verdict = "GAP+RULE " + obs
		case len(c.expected) == 0:
			verdict = "gap"
		case len(expRules) == 0:
			verdict = "SKIP-INTENT exp=" + exp
		case containsAll(stripSev(all), expRules):
			verdict = "HIT"
			if extra := diff(stripSev(all), c.expected); len(extra) > 0 {
				verdict += " +" + strings.Join(extra, ",")
			}
		default:
			verdict = "MISS exp=" + exp + " obs=" + obs
			miss++
		}
		fmt.Printf("%-5s %-11s %-58s %s\n", c.id, c.tactic, trunc(c.cmd, 58), verdict)
	}
	// X-1（R8.4 审计）：门禁判定编码进退出码——此前无条件 exit 0，
	// 「exit=0 即门禁过」的历史用法全部无效（含改名轮的等价证明记录）。
	if fpHit > 0 || miss > 0 {
		fmt.Printf("GATE FAIL: fp_hit=%d miss=%d\n", fpHit, miss)
		os.Exit(1)
	}
	fmt.Println("GATE PASS")
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func stripSev(xs []string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if i := strings.IndexByte(x, '('); i > 0 {
			out = append(out, x[:i])
		} else {
			out = append(out, x)
		}
	}
	return out
}

func containsAll(have, want []string) bool {
	for _, w := range want {
		if !contains(have, w) {
			return false
		}
	}
	return true
}

func diff(have, want []string) []string {
	var out []string
	for _, h := range have {
		if !contains(want, h) {
			out = append(out, h)
		}
	}
	return out
}
