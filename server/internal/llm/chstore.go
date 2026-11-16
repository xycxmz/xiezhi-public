// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

const createTriageDDL = `
CREATE TABLE IF NOT EXISTS xiezhi.llm_triage (
	ts DateTime64(3),
	alert_ts DateTime64(3),
	agent_id String,
	rule_id String,
	state LowCardinality(String),
	confidence Float64,
	reasoning String,
	tactic String,
	model String,
	latency_ms UInt32,
	tokens_in UInt32,
	tokens_out UInt32
) ENGINE = MergeTree
ORDER BY (ts, rule_id)`

const insertTriageSQL = "INSERT INTO xiezhi.llm_triage (ts, alert_ts, agent_id, rule_id, state, confidence, reasoning, tactic, model, latency_ms, tokens_in, tokens_out)"

// CHStore 是 llm_triage 的 ClickHouse 适配器，driver.Conn 由 main 传入
// （复用 store.OpenCH 的连接；建表幂等）。
type CHStore struct {
	conn driver.Conn
}

func NewCHStore(conn driver.Conn) *CHStore { return &CHStore{conn: conn} }

// EnsureTable 幂等建表（main 启动时调用，失败只降级研判落库，大声说）。
func (s *CHStore) EnsureTable(ctx context.Context) error {
	if err := s.conn.Exec(ctx, createTriageDDL); err != nil {
		return fmt.Errorf("ensure llm_triage schema: %w", err)
	}
	return nil
}

func (s *CHStore) SaveTriage(ctx context.Context, row TriageRow) error {
	if row.TsMs == 0 {
		row.TsMs = time.Now().UnixMilli()
	}
	return s.conn.Exec(ctx,
		"INSERT INTO xiezhi.llm_triage (ts, alert_ts, agent_id, rule_id, state, confidence, reasoning, tactic, model, latency_ms, tokens_in, tokens_out) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		time.UnixMilli(row.TsMs), time.UnixMilli(row.AlertTsMs), row.AgentID, row.RuleID,
		string(row.State), row.Confidence, row.Reasoning, row.Tactic, row.Model,
		uint32(row.LatencyMs), uint32(row.TokensIn), uint32(row.TokensOut))
}

// RecentTriages 按 ts 倒序查询（/triage 用）。LIMIT 字面量拼接已钳制 int，
// 与 store 包 RecentEvents 同纪律。
func (s *CHStore) RecentTriages(ctx context.Context, q TriageQuery) ([]map[string]any, error) {
	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var conds []string
	var args []any
	if q.State != "" {
		conds = append(conds, "state = ?")
		args = append(args, q.State)
	}
	if q.RuleID != "" {
		conds = append(conds, "rule_id = ?")
		args = append(args, q.RuleID)
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	sql := fmt.Sprintf(
		"SELECT ts, alert_ts, agent_id, rule_id, state, confidence, reasoning, tactic, model, latency_ms, tokens_in, tokens_out FROM xiezhi.llm_triage %s ORDER BY ts DESC LIMIT %s",
		where, strconv.Itoa(limit))
	rows, err := s.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var ts, alertTs time.Time
		var agentID, ruleID, state, reasoning, tactic, model string
		var confidence float64
		var latencyMs, tokensIn, tokensOut uint32
		if err := rows.Scan(&ts, &alertTs, &agentID, &ruleID, &state, &confidence, &reasoning, &tactic, &model, &latencyMs, &tokensIn, &tokensOut); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"ts": ts.UTC().Format(time.RFC3339Nano), "alert_ts": alertTs.UTC().Format(time.RFC3339Nano),
			"agent_id": agentID, "rule_id": ruleID, "state": state, "confidence": confidence,
			"reasoning": reasoning, "tactic": tactic, "model": model,
			"latency_ms": latencyMs, "tokens_in": tokensIn, "tokens_out": tokensOut,
		})
	}
	return out, rows.Err()
}

var (
	_ TriageStore  = (*CHStore)(nil)
	_ TriageReader = (*CHStore)(nil)
)

// Usage24h 汇总近 24h 研判条数、token 用量与平均延迟（控制台成本卡；
// 成本=token 量 × 供应商单价，单价随行就市不落码）。
func (s *CHStore) Usage24h(ctx context.Context) (map[string]uint64, error) {
	// 聚合拆行取值（clickhouse-go 对混合聚合列的 QueryRow.Scan 有类型
	// 协商坑）；失败大声而非静默吞掉 stats 段。
	rows, err := s.conn.Query(ctx,
		`SELECT count(), sum(tokens_in), sum(tokens_out), avg(latency_ms)
		 FROM xiezhi.llm_triage WHERE ts > now() - INTERVAL 24 HOUR`)
	if err != nil {
		slog.Warn("llm usage query failed", "err", err)
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return map[string]uint64{}, nil
	}
	var n, tin, tout uint64
	var lat float64
	if err := rows.Scan(&n, &tin, &tout, &lat); err != nil {
		slog.Warn("llm usage scan failed", "err", err)
		return nil, err
	}
	if n == 0 || math.IsNaN(lat) { // S-5：空窗 avg 返回 NaN，uint64 转换未定义
		lat = 0
	}
	return map[string]uint64{
		"count": n, "tokens_in": tin, "tokens_out": tout,
		"avg_latency_ms": uint64(lat),
	}, nil
}
