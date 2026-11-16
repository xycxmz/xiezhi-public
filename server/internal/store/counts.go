// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"time"
)

// 控制台聚合查询（/api/rules /api/stats）：全部 GROUP BY 计数，24h 窗口，
// 无索引也能走 ORDER BY 键前缀扫描；数据量增长后再按需加 TTL/物化。

// AlertCountsByRule 统计时间窗内每条规则的告警数。
func (s *CHStore) AlertCountsByRule(ctx context.Context, since time.Time) (map[string]uint64, error) {
	return s.countBy(ctx, "SELECT rule_id, count() FROM xiezhi.alerts WHERE ts >= ? GROUP BY rule_id", since)
}

// AlertCountsBySeverity 统计时间窗内各严重度的告警数。
func (s *CHStore) AlertCountsBySeverity(ctx context.Context, since time.Time) (map[string]uint64, error) {
	return s.countBy(ctx, "SELECT severity, count() FROM xiezhi.alerts WHERE ts >= ? GROUP BY severity", since)
}

// EventCountsByType 统计时间窗内各事件类型的数量。
func (s *CHStore) EventCountsByType(ctx context.Context, since time.Time) (map[string]uint64, error) {
	return s.countBy(ctx, "SELECT event_type, count() FROM xiezhi.events_raw WHERE ts >= ? GROUP BY event_type", since)
}

func (s *CHStore) countBy(ctx context.Context, query string, since time.Time) (map[string]uint64, error) {
	rows, err := s.conn.Query(ctx, query, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]uint64{}
	for rows.Next() {
		var k string
		var n uint64
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}
