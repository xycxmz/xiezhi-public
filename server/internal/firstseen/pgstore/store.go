// SPDX-License-Identifier: Apache-2.0

// Package pgstore 是 firstseen 的 PG 持久化实现（env XIEZHI_PG_DSN，
// database/sql + pgx stdlib 驱动）。建表走 CREATE TABLE IF NOT EXISTS
// 附加式演进（项目惯例：无迁移文件）。
//
// 依赖声明：github.com/jackc/pgx/v5 未进 go.mod（本委托无权改），由主会话
// 统一补齐后本包方可编译。
package pgstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/xycxmz/xiezhi-public/server/internal/firstseen"
)

const ddl = `CREATE TABLE IF NOT EXISTS first_seen (
	key       TEXT PRIMARY KEY,
	first_ts  BIGINT NOT NULL,
	last_ts   BIGINT NOT NULL,
	hit_count BIGINT NOT NULL DEFAULT 0
)`

type Store struct {
	db *sql.DB
}

func Open(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("firstseen pgstore open: %w", err)
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(ddl); err != nil {
		db.Close()
		return nil, fmt.Errorf("firstseen pgstore ddl: %w", err)
	}
	return &Store{db: db}, nil
}

// Upsert 单语句批量 upsert。isNew 判定用 xmax=0 技巧：
//
//	INSERT ... ON CONFLICT (key) DO UPDATE SET ... RETURNING key, (xmax = 0)
//
// 新插入的行 xmax=0；走冲突更新路径的行，其新行版本的 xmax 会被写成本事务
// xid（实务上恒非 0）。hit_count 每次自增 EXCLUDED.hit_count，保证冲突路径
// 行版本必然变化，排掉「UPDATE 内容全同被优化跳过、xmax 留 0 误判为新」的
// 边角。批内键已由上层 mergeObs 去重，不存在语句内同键多行。last_ts 取
// GREATEST 保证乱序批次下仍单调。
func (s *Store) Upsert(ctx context.Context, obs []firstseen.Obs) ([]int, error) {
	if len(obs) == 0 {
		return nil, nil
	}
	var sb strings.Builder
	args := make([]any, 0, len(obs)*4)
	sb.WriteString("INSERT INTO first_seen (key, first_ts, last_ts, hit_count) VALUES ")
	for i, o := range obs {
		if i > 0 {
			sb.WriteByte(',')
		}
		b := i * 4
		fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d)", b+1, b+2, b+3, b+4)
		args = append(args, o.Key, o.TsMs, o.TsMs, o.Count)
	}
	sb.WriteString(" ON CONFLICT (key) DO UPDATE SET last_ts = GREATEST(first_seen.last_ts, EXCLUDED.last_ts), hit_count = first_seen.hit_count + EXCLUDED.hit_count RETURNING key, (xmax = 0) AS is_new")

	rows, err := s.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	idx := make(map[string]int, len(obs))
	for i, o := range obs {
		idx[o.Key] = i
	}
	var newIdx []int
	for rows.Next() {
		var key string
		var isNew bool
		if err := rows.Scan(&key, &isNew); err != nil {
			return nil, err
		}
		if isNew {
			if i, ok := idx[key]; ok {
				newIdx = append(newIdx, i)
			}
		}
	}
	return newIdx, rows.Err()
}

func (s *Store) Close() error { return s.db.Close() }
