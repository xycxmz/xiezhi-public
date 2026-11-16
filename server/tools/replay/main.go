// SPDX-License-Identifier: Apache-2.0

// Command replay 是回放评测工具（M4）：从 ClickHouse 拉历史事件（只读，不写
// 任何表——刻意不经 store.OpenCH，它会跑 CREATE TABLE DDL），离线喂给规则
// 引擎 + first-seen（纯内存 store），stdout 输出 markdown 基线报告：规则命中
// 分布、首见键分布、事件吞吐、丢弃计数。
//
// 用法：
//
//	go run ./tools/replay \
//	  -dsn clickhouse://default:pass@127.0.0.1:19000/xiezhi \
//	  -from 2026-11-11T00:00:00+08:00 -to 2026-11-12T00:00:00+08:00 \
//	  -rules rules/seed -limit 500000 > replay.md
//
// 语义注记（读报告前必看）：
//   - first-seen 回放是冷启动 store：窗口内每个 distinct 键都算首见。生产
//     语义是全历史首见，回放值是它的上界（新部署第一天的告警面）。
//   - 规则回放关闭了生产限速（10/min/rule/agent）：报告规则命中全集，线上
//     告警量还会被限速压低。
//   - exe 白名单沿用 env XIEZHI_FIRSTSEEN_EXE_PREFIXES（默认
//     /usr,/bin,/sbin,/lib,/opt,/snap,/etc），白名单内 exe 键计入统计但
//     生产不告警。
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/xycxmz/xiezhi-public/proto"
	"github.com/xycxmz/xiezhi-public/server/internal/firstseen"
	"github.com/xycxmz/xiezhi-public/server/internal/pipeline"
	"github.com/xycxmz/xiezhi-public/server/internal/rules"
	"github.com/xycxmz/xiezhi-public/server/internal/store"
)

func main() {
	if err := run(); err != nil {
		slog.Error("replay exited", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dsn     = flag.String("dsn", "", "ClickHouse DSN（clickhouse://user:pass@host:19000/hids），只读使用")
		fromS   = flag.String("from", "", "窗口起点 RFC3339（必填）")
		toS     = flag.String("to", "", "窗口终点 RFC3339（默认 now）")
		agentID = flag.String("agent", "", "只回放该 agent_id（空=全部）")
		ruleDir = flag.String("rules", "", "规则目录（空=跳过规则回放）")
		limit   = flag.Int("limit", 100000, "最多拉取事件数")
	)
	flag.Parse()

	if *dsn == "" || *fromS == "" {
		return fmt.Errorf("-dsn 与 -from 必填")
	}
	from, err := time.Parse(time.RFC3339, *fromS)
	if err != nil {
		return fmt.Errorf("-from: %w", err)
	}
	to := time.Now()
	if *toS != "" {
		if to, err = time.Parse(time.RFC3339, *toS); err != nil {
			return fmt.Errorf("-to: %w", err)
		}
	}
	if to.Before(from) {
		return fmt.Errorf("-to 早于 -from")
	}
	if *limit < 1 {
		*limit = 1
	}
	if *limit > 1_000_000 {
		*limit = 1_000_000
	}

	ctx := context.Background()
	conn, err := openCH(ctx, *dsn)
	if err != nil {
		return err
	}
	defer conn.Close()

	ruleSink := &captureSink{}
	var eng *rules.Engine
	if *ruleDir != "" {
		// 队列放大防回放喂入快于 worker 排干；限速抬到天文数字=关闭（见注记）
		eng, err = rules.New(*ruleDir, ruleSink,
			rules.WithQueueCap(1<<19), rules.WithAlertRateLimit(1<<30, time.Hour))
		if err != nil {
			return err
		}
	}

	fsSink := &captureSink{}
	mem := newMemStore()
	// 队列 256k 缓冲吸收喂入/排干速度差；真溢出会体现在报告的丢弃计数里
	fs := firstseen.New(mem, fsSink, firstseen.Config{QueueSize: 1 << 18})

	rep := newReport()
	rep.From, rep.To, rep.AgentFilter, rep.Limit = from, to, *agentID, *limit
	rep.RulesEnabled = eng != nil
	feedStart := time.Now()
	rows, err := fetchEvents(ctx, conn, from, to, *agentID, *limit)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r store.Row
		if err := rows.Scan(&r.Ts, &r.AgentID, &r.Hostname, &r.EventType, &r.Body); err != nil {
			rows.Close()
			return err
		}
		rep.Events++
		rep.agents[r.AgentID] = struct{}{}
		rep.Types[r.EventType]++
		ev := &pb.Event{}
		if err := protojson.Unmarshal([]byte(r.Body), ev); err != nil {
			rep.BadBody++
			continue
		}
		if eng != nil {
			eng.Handle(ctx, ev)
		}
		fs.Handle(ctx, ev)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	rep.FeedElapsed = time.Since(feedStart)

	if eng != nil {
		eng.Close() // 排干队列，让 worker 处理完全部事件
		rep.RulesStats = eng.Stats()
		rep.RuleHits = tallyRuleHits(ruleSink.snapshot())
	}
	fs.Close()
	rep.FSObs = mem.obsInOrder()
	rep.FSWhitelisted, rep.FSByKind, rep.FSByHost = classifyObs(rep.FSObs, firstseen.ExePrefixesFromEnv())
	rep.FSDigestAlerts = len(fsSink.snapshot())
	rep.FSDropped = fs.Dropped()
	rep.FSFlushFailed = fs.FlushFailed()

	return renderReport(os.Stdout, rep)
}

// openCH 只建连+Ping，不跑任何 DDL：本工具对 CH 严格只读。
func openCH(ctx context.Context, dsn string) (driver.Conn, error) {
	opt, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	conn, err := clickhouse.Open(opt)
	if err != nil {
		return nil, fmt.Errorf("open clickhouse: %w", err)
	}
	if err := conn.Ping(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ping clickhouse: %w", err)
	}
	return conn, nil
}

// fetchEvents 按时间窗+agent 拉历史事件，时间升序。LIMIT 用字面量：与
// store.RecentEvents 同因，clickhouse-go 的 ? 绑定走 settings 路径，LIMIT
// 位置不可靠；limit 已钳制无注入面。
func fetchEvents(ctx context.Context, conn driver.Conn, from, to time.Time, agentID string, limit int) (driver.Rows, error) {
	q := "SELECT ts, agent_id, hostname, event_type, body FROM xiezhi.events_raw WHERE ts >= ? AND ts <= ?"
	args := []any{from, to}
	if agentID != "" {
		q += " AND agent_id = ?"
		args = append(args, agentID)
	}
	q += " ORDER BY ts LIMIT " + strconv.Itoa(limit)
	return conn.Query(ctx, q, args...)
}

// captureSink 收集回放期产生的全部告警（规则命中 / first-seen digest）。
type captureSink struct {
	mu     sync.Mutex
	alerts []pipeline.Alert
}

func (c *captureSink) EmitAlert(_ context.Context, a *pipeline.Alert) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alerts = append(c.alerts, *a)
}

func (c *captureSink) snapshot() []pipeline.Alert {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]pipeline.Alert(nil), c.alerts...)
}

func (c *captureSink) Close() {}

// memFSStore 是 firstseen.Store 的纯内存实现：回放冷启动，窗口内首见=distinct
// 键；保插入序让报告确定。
type memFSStore struct {
	mu    sync.Mutex
	order []firstseen.Obs
	seen  map[string]int
}

func newMemStore() *memFSStore { return &memFSStore{seen: make(map[string]int)} }

func (m *memFSStore) Upsert(_ context.Context, obs []firstseen.Obs) ([]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var idx []int
	for i, o := range obs {
		if _, ok := m.seen[o.Key]; ok {
			continue
		}
		if o.Count < 1 {
			o.Count = 1
		}
		m.seen[o.Key] = len(m.order)
		m.order = append(m.order, o)
		idx = append(idx, i)
	}
	return idx, nil
}

func (m *memFSStore) obsInOrder() []firstseen.Obs {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]firstseen.Obs(nil), m.order...)
}

func (m *memFSStore) Close() error { return nil }

type kv struct {
	K string
	V int
}

// topN 按 value 降序、key 升序取前 n，报告表格确定序。
func topN(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].V != out[j].V {
			return out[i].V > out[j].V
		}
		return out[i].K < out[j].K
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// tallyRuleHits 按规则聚合告警数（回放报告的规则命中分布）。
func tallyRuleHits(alerts []pipeline.Alert) map[string]int {
	m := make(map[string]int, len(alerts))
	for _, a := range alerts {
		m[a.RuleID]++
	}
	return m
}

// classifyObs 把首见观察按 kind / host 聚合，并单列白名单内 exe（生产只记录
// 不告警的那部分）。
func classifyObs(obs []firstseen.Obs, exePrefixes []string) (whitelistedExe int, byKind, byHost map[string]int) {
	byKind = make(map[string]int)
	byHost = make(map[string]int)
	for _, o := range obs {
		byKind[o.Kind]++
		byHost[o.Host]++
		if o.Kind == firstseen.KindExe {
			if exe, ok := firstseen.KeyExePath(o.Key); ok && matchAnyPrefix(exe, exePrefixes) {
				whitelistedExe++
			}
		}
	}
	return
}

func matchAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// report 是渲染层的全部输入（纯数据），renderReport 只做格式化。
type report struct {
	From, To    time.Time
	AgentFilter string
	Limit       int
	Events      int64
	BadBody     int64
	FeedElapsed time.Duration
	Types       map[string]int
	agents      map[string]struct{}

	RulesEnabled bool
	RulesStats   rules.Stats
	RuleHits     map[string]int

	FSObs           []firstseen.Obs
	FSWhitelisted   int
	FSByKind        map[string]int
	FSByHost        map[string]int
	FSDigestAlerts  int
	FSDropped       uint64
	FSFlushFailed   uint64
}

func newReport() *report {
	return &report{Types: map[string]int{}, agents: map[string]struct{}{}}
}

func renderReport(w io.Writer, r *report) error {
	agentFilter := r.AgentFilter
	if agentFilter == "" {
		agentFilter = "全部"
	}
	trunc := ""
	if r.Events >= int64(r.Limit) {
		trunc = fmt.Sprintf("（已达 LIMIT %d，结果可能被截断，加大 -limit 复跑）", r.Limit)
	}
	eps := 0.0
	if r.FeedElapsed > 0 {
		eps = float64(r.Events) / r.FeedElapsed.Seconds()
	}

	if _, err := fmt.Fprintf(w, "# HIDS 回放评测报告\n\n"); err != nil {
		return err
	}
	fprintf := func(format string, args ...any) error {
		_, err := fmt.Fprintf(w, format, args...)
		return err
	}
	if err := fprintf("- 窗口: %s → %s（agent: %s）\n", r.From.Format(time.RFC3339), r.To.Format(time.RFC3339), agentFilter); err != nil {
		return err
	}
	if err := fprintf("- 事件: %d%s / 解析失败 %d / agent 数 %d\n", r.Events, trunc, r.BadBody, len(r.agents)); err != nil {
		return err
	}
	if err := fprintf("- 回放吞吐: %d events / %s（%.0f ev/s）\n", r.Events, r.FeedElapsed.Truncate(time.Millisecond), eps); err != nil {
		return err
	}

	if err := fprintf("\n## 规则引擎\n\n"); err != nil {
		return err
	}
	if !r.RulesEnabled {
		if err := fprintf("未启用（-rules 为空）。\n"); err != nil {
			return err
		}
	} else {
		st := r.RulesStats
		if err := fprintf("- 规则 %d 条（version %s, rejected %d）；引擎处理 %d / 入队丢弃 %d / panic %d\n",
			st.RulesLoaded, st.Version, st.RulesRejected, st.EventsProcessed, st.EventsDropped, st.Panics); err != nil {
			return err
		}
		if err := fprintf("- 命中 %d 条（回放已关闭生产限速 10/min/rule/agent，线上量会被限速压低；限速口径丢弃 %d）\n\n",
			st.AlertsEmitted, st.AlertsLimited); err != nil {
			return err
		}
		if err := writeKVTable(w, topN(r.RuleHits, 20), "规则", "命中"); err != nil {
			return err
		}
	}

	if err := fprintf("\n## first-seen（冷启动：窗口内 distinct 键 = 新部署首日告警面上界）\n\n"); err != nil {
		return err
	}
	if err := fprintf("- 键 %d（白名单内 exe %d：生产只记录不告警）\n", len(r.FSObs), r.FSWhitelisted); err != nil {
		return err
	}
	if err := fprintf("- digest 告警 %d 条（回放收尾 flushAll，按事件小时聚合）\n", r.FSDigestAlerts); err != nil {
		return err
	}
	if err := fprintf("- 队列丢弃 %d / flush 失败 %d\n\n", r.FSDropped, r.FSFlushFailed); err != nil {
		return err
	}
	if err := writeKVTable(w, topN(r.FSByKind, 10), "kind", "新键数"); err != nil {
		return err
	}
	if err := fprintf("\n### 新键最多的主机（top 10）\n\n"); err != nil {
		return err
	}
	if err := writeKVTable(w, topN(r.FSByHost, 10), "主机", "新键数"); err != nil {
		return err
	}

	if err := fprintf("\n## 事件类型分布\n\n"); err != nil {
		return err
	}
	return writeKVTable(w, topN(r.Types, 30), "类型", "数量")
}

func writeKVTable(w io.Writer, rows []kv, name, value string) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintf(w, "（无数据）\n")
		return err
	}
	if _, err := fmt.Fprintf(w, "| %s | %s |\n|---|---|\n", name, value); err != nil {
		return err
	}
	for _, r := range rows {
		if _, err := fmt.Fprintf(w, "| %s | %d |\n", r.K, r.V); err != nil {
			return err
		}
	}
	return nil
}
