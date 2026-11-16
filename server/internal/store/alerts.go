// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	pipeline "github.com/xycxmz/xiezhi-public/server/internal/pipeline"
)

const createAlertsDDL = `
CREATE TABLE IF NOT EXISTS xiezhi.alerts (
	ts DateTime64(3),
	agent_id String,
	hostname String,
	rule_id String,
	severity LowCardinality(String),
	mitre String,
	summary String,
	event_ref String
) ENGINE = MergeTree
ORDER BY (ts, rule_id)`

// 告警确认工作流（R6.4）：确认状态独立表而非 alerts 表 mutation——CH 的
// mutation 重且异步，append-only 的 ack 表 + 查询侧内存过滤是惯例做法。
// 键=(ts_ms, rule_id, agent_id)：firstseen digest 批量告警会同毫秒同规则
// 跨主机触发，缺 agent 维度时 ack 一条会连带隐藏他机告警（R8.4 审计 S-1）。
const createAlertAckDDL = `
CREATE TABLE IF NOT EXISTS xiezhi.alert_ack (
	ts_ms Int64,
	rule_id String,
	agent_id String DEFAULT '',
	ack_ts DateTime DEFAULT now(),
	ack_by String DEFAULT 'console'
) ENGINE = MergeTree
ORDER BY (ts_ms, rule_id, agent_id)`

// 存量 alert_ack 表补 agent_id 列（幂等）。CREATE IF NOT EXISTS 不触碰
// 已存表，故迁移单独跑；排序键不重排——MergeTree 改排序键需 mutation，
// 查询/过滤不依赖它。
const migrateAlertAckAgentDDL = "ALTER TABLE xiezhi.alert_ack ADD COLUMN IF NOT EXISTS agent_id String DEFAULT ''"

const insertAlertsSQL = "INSERT INTO xiezhi.alerts (ts, agent_id, hostname, rule_id, severity, mitre, summary, event_ref)"

// AlertRow 是 Alert 的 CH 行投影。
type AlertRow struct {
	Ts       time.Time
	AgentID  string
	Hostname string
	RuleID   string
	Severity string
	Mitre    string
	Summary  string
	EventRef string
}

// EnsureAlertsTable 建告警与确认表（幂等）。OpenCH 后调用。
func (s *CHStore) EnsureAlertsTable(ctx context.Context) error {
	if err := s.conn.Exec(ctx, createAlertsDDL); err != nil {
		return fmt.Errorf("ensure alerts schema: %w", err)
	}
	if err := s.conn.Exec(ctx, createAlertAckDDL); err != nil {
		return fmt.Errorf("ensure alert_ack schema: %w", err)
	}
	if err := s.conn.Exec(ctx, migrateAlertAckAgentDDL); err != nil {
		return fmt.Errorf("migrate alert_ack agent_id: %w", err)
	}
	return nil
}

// AckAlert 确认一条告警（幂等：同键重复插入 MergeTree 去重语义）。
// agentID 入键：同毫秒同规则跨主机的告警须分别确认（S-1）。
func (s *CHStore) AckAlert(ctx context.Context, tsMs int64, ruleID, agentID, by string) error {
	if by == "" {
		by = "console"
	}
	if err := s.conn.Exec(ctx,
		"INSERT INTO xiezhi.alert_ack (ts_ms, rule_id, agent_id, ack_by) VALUES (?, ?, ?, ?)",
		tsMs, ruleID, agentID, by); err != nil {
		return fmt.Errorf("ack alert: %w", err)
	}
	return nil
}

// AckedKeys 返回近 7 天已确认告警的键集（"tsMs|ruleId|agentId"），查询侧内存过滤用。
func (s *CHStore) AckedKeys(ctx context.Context) (map[string]bool, error) {
	rows, err := s.conn.Query(ctx,
		"SELECT ts_ms, rule_id, agent_id FROM xiezhi.alert_ack WHERE ack_ts > now() - INTERVAL 7 DAY")
	if err != nil {
		return nil, fmt.Errorf("query acked: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var ms int64
		var rule, agent string
		if err := rows.Scan(&ms, &rule, &agent); err != nil {
			return nil, err
		}
		out[fmt.Sprintf("%d|%s|%s", ms, rule, agent)] = true
	}
	return out, rows.Err()
}

// SendAlerts 批量写告警。
func (s *CHStore) SendAlerts(ctx context.Context, rows []AlertRow) error {
	batch, err := s.conn.PrepareBatch(ctx, insertAlertsSQL)
	if err != nil {
		return err
	}
	defer batch.Close()
	skipped := 0
	for _, r := range rows {
		if err := batch.Append(r.Ts, r.AgentID, r.Hostname, r.RuleID, r.Severity, r.Mitre, r.Summary, r.EventRef); err != nil {
			skipped++
		}
	}
	if skipped > 0 {
		slog.Warn("clickhouse alert rows skipped on append", "skipped", skipped)
	}
	return batch.Send()
}

// AlertSink 把 pipeline.Alert 攒批写 CH（500 条或 1s）。
// 检测层绝不等待存储：队列满丢弃计数（与 events batcher 同纪律）。
type AlertSink struct {
	store     AlertWriter
	ch        chan *pipeline.Alert
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	drop      atomic.Uint64 // F-(C-2)：EmitAlert 多 goroutine 并发，原子防计数丢失
	// broadcast 是可选的即时出口（SSE hub）：EmitAlert 入口 O(1) 调用，
	// 慢消费者由 hub 侧丢弃，绝不阻塞检测链。
	broadcast func([]byte)
}

// SetBroadcast 注入即时广播出口（SSE）。须在 Wrap/投产前调用一次。
func (s *AlertSink) SetBroadcast(fn func([]byte)) { s.broadcast = fn }

// AlertWriter 抽象 CH 写入以便测试。
type AlertWriter interface {
	SendAlerts(ctx context.Context, rows []AlertRow) error
}

func NewAlertSink(w AlertWriter) *AlertSink {
	s := &AlertSink{
		store: w,
		ch:    make(chan *pipeline.Alert, 4096),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go s.loop()
	return s
}

func (s *AlertSink) loop() {
	defer close(s.done)
	buf := make([]AlertRow, 0, 500)
	flush := func() {
		if len(buf) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := s.store.SendAlerts(ctx, buf); err != nil {
			slog.Warn("alerts flush failed", "err", err, "rows", len(buf))
		}
		cancel()
		buf = buf[:0]
	}
	appendOne := func(a *pipeline.Alert) {
		buf = append(buf, AlertRow{
			Ts: time.UnixMilli(a.TsMs), AgentID: a.AgentID, Hostname: a.Hostname,
			RuleID: a.RuleID, Severity: a.Severity, Mitre: a.Mitre,
			Summary: a.Summary, EventRef: a.EventRef,
		})
		if len(buf) >= 500 {
			flush()
		}
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case a := <-s.ch:
			appendOne(a)
		case <-t.C:
			flush()
		case <-s.stop:
			// 排干队列后终刷：由 loop 自己消费，不再靠旁路 goroutine 抢队列
			// （旁路的空 case 会把告警丢掉）。调用方约定先停 pipeline 再 Close。
			for {
				select {
				case a := <-s.ch:
					appendOne(a)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (s *AlertSink) EmitAlert(_ context.Context, a *pipeline.Alert) {
	if s.broadcast != nil {
		if b, err := json.Marshal(a); err == nil {
			s.broadcast(b)
		}
	}
	select {
	case s.ch <- a:
	default:
		n := s.drop.Add(1)
		if n == 1 || n%1000 == 0 {
			slog.Warn("alert sink queue full, dropping", "dropped", n)
		}
	}
}

// Close 停消费循环：loop 排干缓冲队列并终刷后才退出（done 关闭即刷完），
// 关停不再丢弃已缓冲的告警，也不依赖 ticker 碰运气。
func (s *AlertSink) Close() {
	s.closeOnce.Do(func() { close(s.stop) })
	<-s.done
}

// NATSAlertPublisher 是可选的告警第二出口（subject xiezhi.alerts）。
type NATSAlertPublisher struct {
	Publish func(subject string, data []byte) error
}

func (n *NATSAlertPublisher) Wrap(next pipeline.Sink) pipeline.Sink {
	return &chainedSink{nats: n, next: next}
}

type chainedSink struct {
	nats *NATSAlertPublisher
	next pipeline.Sink
}

func (c *chainedSink) EmitAlert(ctx context.Context, a *pipeline.Alert) {
	if c.nats != nil && c.nats.Publish != nil {
		if b, err := json.Marshal(a); err == nil {
			if err := c.nats.Publish("xiezhi.alerts", b); err != nil {
				slog.Warn("nats alert publish failed", "err", err)
			}
		}
	}
	c.next.EmitAlert(ctx, a)
}

func (c *chainedSink) Close() { c.next.Close() }

// compile-time：AlertSink 实现 pipeline.Sink
var _ pipeline.Sink = (*AlertSink)(nil)

// RecentAlerts 查询（/alerts API 用）。
type AlertQuery struct {
	Limit    int
	RuleID   string
	Severity string
	AgentID  string
}

func (s *CHStore) RecentAlerts(ctx context.Context, q AlertQuery) ([]map[string]any, error) {
	where := ""
	conds := []string{}
	args := []any{}
	if q.RuleID != "" {
		conds = append(conds, "a.rule_id = ?")
		args = append(args, q.RuleID)
	}
	if q.Severity != "" {
		conds = append(conds, "a.severity = ?")
		args = append(args, q.Severity)
	}
	if q.AgentID != "" {
		conds = append(conds, "a.agent_id = ?")
		args = append(args, q.AgentID)
	}
	if len(conds) > 0 {
		where = "WHERE " + conds[0]
		for _, c := range conds[1:] {
			where += " AND " + c
		}
	}
	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	// LEFT JOIN llm_triage（advisory）：秒级键 + agent_id + LIMIT 1 BY
	// 每键单行（F-002：同秒同规则多告警时裸 join 笛卡尔扇出，研判结论会
	// 错挂到别的告警上）；无研判的告警字段为 null。
	rows, err := s.conn.Query(ctx, fmt.Sprintf(`
SELECT a.ts, a.agent_id, a.hostname, a.rule_id, a.severity, a.mitre, a.summary,
       t.state, t.confidence, t.reasoning
FROM xiezhi.alerts a
LEFT JOIN (
  SELECT alert_ts, rule_id, agent_id, state, confidence, reasoning
  FROM xiezhi.llm_triage
  WHERE alert_ts > now() - INTERVAL 7 DAY
  ORDER BY ts DESC LIMIT 1 BY toStartOfSecond(alert_ts), rule_id, agent_id
) t
  ON toUnixTimestamp(toStartOfSecond(a.ts)) = toUnixTimestamp(toStartOfSecond(t.alert_ts))
 AND a.rule_id = t.rule_id AND a.agent_id = t.agent_id
%s ORDER BY a.ts DESC LIMIT %d`, where, limit), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var ts time.Time
		var agentID, hostname, ruleID, severity, mitre, summary string
		var state *string
		var conf *float64
		var reasoning *string
		if err := rows.Scan(&ts, &agentID, &hostname, &ruleID, &severity, &mitre, &summary, &state, &conf, &reasoning); err != nil {
			return nil, err
		}
		row := map[string]any{
			"ts": ts.UTC().Format(time.RFC3339Nano), "ts_ms": ts.UnixMilli(),
			"agent_id": agentID, "hostname": hostname,
			"rule_id": ruleID, "severity": severity, "mitre": mitre, "summary": summary,
		}
		if state != nil {
			row["triage_state"] = *state
			if conf != nil {
				row["triage_confidence"] = *conf
			}
			if reasoning != nil {
				row["triage_reasoning"] = truncRunesStr(*reasoning, 600)
			}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// EventRefByAlert 取告警的触发事件 JSON（溯源图一期：钻取进程键用）。
// 键含 agent_id：firstseen 类规则在多机同秒同规则触发是常态，缺它会把
// 别的主机的 event_ref 错配到本告警（R8.4 审计 F-012）。无命中返回空串。
func (s *CHStore) EventRefByAlert(ctx context.Context, tsMs int64, ruleID, agentID string) (string, error) {
	var ref string
	err := s.conn.QueryRow(ctx,
		"SELECT event_ref FROM xiezhi.alerts WHERE toUnixTimestamp(toStartOfSecond(ts)) = ? AND rule_id = ? AND agent_id = ? ORDER BY ts DESC LIMIT 1",
		tsMs/1000, ruleID, agentID).Scan(&ref)
	if err != nil {
		return "", nil // 含 ErrNoRows：告警可能无 ref（deadman 侧产）——非错误
	}
	return ref, nil
}

// truncRunesStr 按字节截断并标记（与 llm 包 truncBytes 同语义的本地版，
// 避免为截断工具引入跨包导出）。
func truncRunesStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}
