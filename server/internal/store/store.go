// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"time"
)

// Row 是事件的存储投影：ClickHouse events_raw 的一行，NATS 也发布同一负载。
type Row struct {
	Ts        time.Time
	AgentID   string
	Hostname  string
	EventType string
	Body      string // protojson 序列化的完整事件
}

// Query 是最近事件查询的过滤条件，Limit 已由调用方钳制。
type Query struct {
	Limit int
	Agent string
	Type  string
}

// RowSender 由真实 ClickHouse 适配器与测试 fake 实现。
type RowSender interface {
	Send(ctx context.Context, rows []Row) error
}

// Querier 由真实 ClickHouse 适配器与测试 fake 实现。
type Querier interface {
	RecentEvents(ctx context.Context, q Query) ([]Row, error)
}
