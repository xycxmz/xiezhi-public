// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

const createDatabaseDDL = "CREATE DATABASE IF NOT EXISTS xiezhi"

const createTableDDL = `
CREATE TABLE IF NOT EXISTS xiezhi.events_raw (
	ts DateTime64(3),
	agent_id String,
	hostname String,
	event_type LowCardinality(String),
	body String
) ENGINE = MergeTree
ORDER BY (ts, agent_id)`

const insertSQL = "INSERT INTO xiezhi.events_raw (ts, agent_id, hostname, event_type, body)"

// CHStore 是 ClickHouse 的真实适配器，同时实现 RowSender 与 Querier。
type CHStore struct {
	conn driver.Conn
}

// OpenCH 按 DSN（clickhouse://user:pass@host:19000/hids）建连，Ping 验证，
// 并幂等确保库与表存在（agent 重装/CH 重建后直接可用）。
func OpenCH(ctx context.Context, dsn string) (*CHStore, error) {
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
	for _, ddl := range []string{createDatabaseDDL, createTableDDL} {
		if err := conn.Exec(ctx, ddl); err != nil {
			conn.Close()
			return nil, fmt.Errorf("ensure schema: %w", err)
		}
	}
	return &CHStore{conn: conn}, nil
}

func (s *CHStore) Close() error { return s.conn.Close() }

// Conn 导出底层连接（llm triage store 等同进程消费者复用，免另开连接）。
func (s *CHStore) Conn() driver.Conn { return s.conn }

// Send 用 prepared batch 写入一批行；单行 Append 失败跳过该行，不废整批。
func (s *CHStore) Send(ctx context.Context, rows []Row) error {
	batch, err := s.conn.PrepareBatch(ctx, insertSQL)
	if err != nil {
		return err
	}
	defer batch.Close()
	skipped := 0
	for _, r := range rows {
		if err := batch.Append(r.Ts, r.AgentID, r.Hostname, r.EventType, r.Body); err != nil {
			skipped++
		}
	}
	if skipped > 0 {
		slog.Warn("clickhouse batch rows skipped on append", "skipped", skipped)
	}
	return batch.Send()
}

// RecentEvents 按时间倒序取最近事件。LIMIT 用字面量而非绑定参数：
// clickhouse-go 的 ? 绑定走 settings 参数路径，LIMIT 位置不可靠；
// Limit 是已钳制的 int，无注入面。
func (s *CHStore) RecentEvents(ctx context.Context, q Query) ([]Row, error) {
	var sb strings.Builder
	sb.WriteString("SELECT ts, agent_id, hostname, event_type, body FROM xiezhi.events_raw")
	var conds []string
	var args []any
	if q.Agent != "" {
		conds = append(conds, "agent_id = ?")
		args = append(args, q.Agent)
	}
	if q.Type != "" {
		conds = append(conds, "event_type = ?")
		args = append(args, q.Type)
	}
	if len(conds) > 0 {
		sb.WriteString(" WHERE ")
		sb.WriteString(strings.Join(conds, " AND "))
	}
	sb.WriteString(" ORDER BY ts DESC LIMIT ")
	sb.WriteString(strconv.Itoa(q.Limit))
	rows, err := s.conn.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Row, 0, q.Limit)
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.Ts, &r.AgentID, &r.Hostname, &r.EventType, &r.Body); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
