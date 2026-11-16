// SPDX-License-Identifier: Apache-2.0

// rejudge 是证据加厚的前后对比工具（R7 验收线）：
// 拉最近 N 条告警，用当前 BuildEvidence 逻辑（含 pid 相关性重排/4KB
// trigger/PG 归档树）重判，统计三态。与产线同款 prompt 与 provider。
//
// 用法（env 与 server 同款：XIEZHI_CH_DSN/XIEZHI_PG_DSN/XIEZHI_LLM_*）：
//
//	go run ./server/tools/rejudge -n 50
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/xycxmz/xiezhi-public/server/internal/llm"
	"github.com/xycxmz/xiezhi-public/server/internal/pipeline"
	sspg "github.com/xycxmz/xiezhi-public/server/internal/session/pgstore"
	"github.com/xycxmz/xiezhi-public/server/internal/store"
)

// chFetcher 与 server 的 chEventFetcher 同逻辑（工具复制，避免 main 包依赖）。
type chFetcher struct{ ch *store.CHStore }

func (f *chFetcher) RecentByAgent(ctx context.Context, agentID string, sinceMs int64, limit int) ([]llm.EventSummary, error) {
	rows, err := f.ch.RecentEvents(ctx, store.Query{Agent: agentID, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]llm.EventSummary, 0, len(rows))
	for _, r := range rows {
		if r.Ts.UnixMilli() < sinceMs {
			continue
		}
		out = append(out, llm.EventSummary{TsMs: r.Ts.UnixMilli(), Type: r.EventType, Body: r.Body})
	}
	return out, nil
}

// pgSubtree 用 PG 归档树实现 llm.SubtreeSource（历史告警的内存树早已
// 归档，正合工具场景）；平铺文本与产线缩进形态略异，信息量等价。
type pgSubtree struct{ db *sspg.Store }

func (p *pgSubtree) SubtreeJSON(host string, pid int32, depth int) (string, error) {
	tr, nodes, err := p.db.QueryLatestTreeByPID(context.Background(), host, pid)
	if err != nil || tr == nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "tree root_pid=%d host=%s nodes=%d\n", tr.RootPid, tr.Host, tr.NodeCount)
	for _, n := range nodes {
		fmt.Fprintf(&b, "  %d <- %d %s %s\n", n.Pid, n.ParentPid, n.Exe, truncStr(n.Argv, 60))
	}
	return b.String(), nil
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

type verdictRow struct {
	rule  string
	state string
	conf  float64
}

func main() {
	n := flag.Int("n", 50, "recent alerts to rejudge")
	flag.Parse()
	ctx := context.Background()

	ch, err := store.OpenCH(ctx, os.Getenv("XIEZHI_CH_DSN"))
	must(err, "open ch")
	defer ch.Close()
	var trees llm.SubtreeSource
	if dsn := os.Getenv("XIEZHI_PG_DSN"); dsn != "" {
		if db, err := sspg.Open(dsn); err == nil {
			defer db.Close()
			trees = &pgSubtree{db: db}
		} else {
			slog.Warn("pg open failed, process_tree 段将为空", "err", err)
		}
	}
	fetcher := &chFetcher{ch: ch}
	cfg, err := llm.ConfigFromEnv()
	must(err, "llm config")
	prov := llm.NewProvider(cfg)

	alerts, err := ch.RecentAlerts(ctx, store.AlertQuery{Limit: *n})
	must(err, "recent alerts")

	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		rows []verdictRow
		sem  = make(chan struct{}, 4)
	)
	for _, ra := range alerts {
		wg.Add(1)
		go func(ra map[string]any) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			a := &pipeline.Alert{
				TsMs: toI(ra["ts_ms"]), AgentID: toS(ra["agent_id"]),
				Hostname: toS(ra["hostname"]), RuleID: toS(ra["rule_id"]),
				Severity: toS(ra["severity"]), Summary: toS(ra["summary"]),
			}
			if ref, err := ch.EventRefByAlert(ctx, a.TsMs, a.RuleID, a.AgentID); err == nil {
				a.EventRef = ref
			}
			// F-007：证据窗锚告警时刻而非当前时刻（与产线 worker 的
			// TriageSinceMin 语义对齐），否则老告警拿到「现在」的无关证据。
			since := a.TsMs - 30*60*1000
			ev, err := llm.BuildEvidence(ctx, a, since, fetcher, trees)
			if err != nil {
				return
			}
			evJSON, err := ev.MarshalBudgeted()
			if err != nil {
				return
			}
			c, err := prov.Complete(ctx, llm.SystemPrompt(), llm.UserPrompt(evJSON))
			if err != nil {
				slog.Warn("rejudge failed", "rule", a.RuleID, "err", err)
				return
			}
			mu.Lock()
			rows = append(rows, verdictRow{rule: a.RuleID, state: string(c.Verdict.State), conf: c.Verdict.Confidence})
			mu.Unlock()
		}(ra)
	}
	wg.Wait()

	cnt := map[string]int{}
	for _, r := range rows {
		cnt[r.state]++
	}
	fmt.Printf("rejudged=%d/%d\n", len(rows), len(alerts))
	for _, s := range []string{"escalate", "insufficient_evidence", "benign_candidate"} {
		fmt.Printf("  %-22s %3d (%.0f%%)\n", s, cnt[s], pct(cnt[s], len(rows)))
	}
	byRule := map[string]map[string]int{}
	for _, r := range rows {
		if byRule[r.rule] == nil {
			byRule[r.rule] = map[string]int{}
		}
		byRule[r.rule][r.state]++
	}
	keys := make([]string, 0, len(byRule))
	for k := range byRule {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println("per-rule:")
	for _, k := range keys {
		fmt.Printf("  %-34s %v\n", k, byRule[k])
	}
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) * 100 / float64(b)
}

func toS(v any) string {
	s, _ := v.(string)
	return s
}

func toI(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case uint64:
		return int64(n)
	}
	return 0
}

func must(err error, what string) {
	if err != nil {
		slog.Error(what+" failed", "err", err)
		os.Exit(1)
	}
}
