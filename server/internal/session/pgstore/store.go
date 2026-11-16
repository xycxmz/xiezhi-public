// SPDX-License-Identifier: Apache-2.0

// Package pgstore 是 session 的 PG 持久化实现（env XIEZHI_PG_DSN，
// database/sql + pgx stdlib 驱动）。建表走 CREATE TABLE IF NOT EXISTS 附加式
// 演进（项目惯例：无迁移文件）。表命名 snake_case。
//
// 依赖声明：github.com/jackc/pgx/v5 未进 go.mod（本委托无权改），由主会话
// 统一补齐后本包方可编译。
package pgstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/xycxmz/xiezhi-public/server/internal/session"
)

// nodeChunk 限定单条多值 INSERT 的行数：驱逐场景整树可达 200k 节点，一次
// 拼完会生成超大 SQL 文本。
const nodeChunk = 500

const ddlTree = `CREATE TABLE IF NOT EXISTS session_tree (
	id               BIGSERIAL PRIMARY KEY,
	host             TEXT    NOT NULL,
	agent_id         TEXT    NOT NULL DEFAULT '',
	boot_id          TEXT    NOT NULL DEFAULT '',
	root_pid         INTEGER NOT NULL,
	root_start_ticks BIGINT  NOT NULL DEFAULT 0,
	first_ts_ms      BIGINT  NOT NULL,
	last_ts_ms       BIGINT  NOT NULL,
	node_count       INTEGER NOT NULL,
	exes             TEXT    NOT NULL DEFAULT '',
	created_ms       BIGINT  NOT NULL DEFAULT 0
)`

const ddlNode = `CREATE TABLE IF NOT EXISTS session_node (
	tree_id     BIGINT  NOT NULL,
	pid         INTEGER NOT NULL,
	start_ticks BIGINT  NOT NULL DEFAULT 0,
	parent_pid  INTEGER NOT NULL DEFAULT 0,
	exe         TEXT    NOT NULL DEFAULT '',
	argv        TEXT    NOT NULL DEFAULT '',
	first_ts_ms BIGINT  NOT NULL DEFAULT 0,
	last_ts_ms  BIGINT  NOT NULL DEFAULT 0,
	exited      BOOLEAN NOT NULL DEFAULT FALSE
)`

const (
	idxTreeHost = `CREATE INDEX IF NOT EXISTS idx_session_tree_host_id ON session_tree (host, id DESC)`
	idxNodeTree = `CREATE INDEX IF NOT EXISTS idx_session_node_tree ON session_node (tree_id)`
	idxNodePid  = `CREATE INDEX IF NOT EXISTS idx_session_node_pid ON session_node (pid)`
)

type Store struct {
	db *sql.DB
}

func Open(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("session pgstore open: %w", err)
	}
	db.SetMaxOpenConns(4)
	for _, q := range []string{ddlTree, ddlNode, idxTreeHost, idxNodeTree, idxNodePid} {
		if _, err := db.Exec(q); err != nil {
			db.Close()
			return nil, fmt.Errorf("session pgstore ddl: %w", err)
		}
	}
	return &Store{db: db}, nil
}

// SaveTree 单事务：树行 RETURNING id，节点分块多值插入。
func (s *Store) SaveTree(ctx context.Context, t *session.TreeRow, nodes []session.NodeRow) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id int64
	err = tx.QueryRowContext(ctx,
		`INSERT INTO session_tree
			(host, agent_id, boot_id, root_pid, root_start_ticks, first_ts_ms, last_ts_ms, node_count, exes, created_ms)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
		t.Host, t.AgentID, t.BootID, t.RootPid, t.RootStartTicks, t.FirstTsMs, t.LastTsMs, t.NodeCount,
		strings.Join(t.Exes, "\x1f"), time.Now().UnixMilli()).Scan(&id)
	if err != nil {
		return err
	}
	for start := 0; start < len(nodes); start += nodeChunk {
		end := min(start+nodeChunk, len(nodes))
		chunk := nodes[start:end]
		var sb strings.Builder
		args := make([]any, 0, len(chunk)*9)
		sb.WriteString("INSERT INTO session_node (tree_id, pid, start_ticks, parent_pid, exe, argv, first_ts_ms, last_ts_ms, exited) VALUES ")
		for i, n := range chunk {
			if i > 0 {
				sb.WriteByte(',')
			}
			b := i * 9
			fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)", b+1, b+2, b+3, b+4, b+5, b+6, b+7, b+8, b+9)
			args = append(args, id, n.Pid, n.StartTicks, n.ParentPid, n.Exe, n.Argv, n.FirstTsMs, n.LastTsMs, n.Exited)
		}
		if _, err := tx.ExecContext(ctx, sb.String(), args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// QueryLatestTreeByPID 取含 (host, pid) 的最近一次归档（id 最大 = 最新落库）。
// 未命中返回 (nil, nil, nil)。
func (s *Store) QueryLatestTreeByPID(ctx context.Context, host string, pid int32) (*session.TreeRow, []session.NodeRow, error) {
	var (
		id   int64
		tr   session.TreeRow
		exes string
	)
	row := s.db.QueryRowContext(ctx,
		`SELECT t.id, t.host, t.agent_id, t.boot_id, t.root_pid, t.root_start_ticks, t.first_ts_ms, t.last_ts_ms, t.node_count, t.exes
		 FROM session_tree t JOIN session_node n ON n.tree_id = t.id
		 WHERE t.host = $1 AND n.pid = $2
		 ORDER BY t.id DESC LIMIT 1`, host, pid)
	err := row.Scan(&id, &tr.Host, &tr.AgentID, &tr.BootID, &tr.RootPid, &tr.RootStartTicks, &tr.FirstTsMs, &tr.LastTsMs, &tr.NodeCount, &exes)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if exes != "" {
		tr.Exes = strings.Split(exes, "\x1f")
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT pid, start_ticks, parent_pid, exe, argv, first_ts_ms, last_ts_ms, exited
		 FROM session_node WHERE tree_id = $1 ORDER BY first_ts_ms, pid`, id)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var nodes []session.NodeRow
	for rows.Next() {
		var n session.NodeRow
		if err := rows.Scan(&n.Pid, &n.StartTicks, &n.ParentPid, &n.Exe, &n.Argv, &n.FirstTsMs, &n.LastTsMs, &n.Exited); err != nil {
			return nil, nil, err
		}
		nodes = append(nodes, n)
	}
	return &tr, nodes, rows.Err()
}

// QueryTreeByProc 按 (pid, start_ticks) 复合键精确定位节点所在树（溯源图
// 一期：告警钻取，键取自告警 event_ref 的 proc）。未命中返回 (nil, nil, nil)。
func (s *Store) QueryTreeByProc(ctx context.Context, pid int32, startTicks uint64) (*session.TreeRow, []session.NodeRow, error) {
	var (
		id   int64
		tr   session.TreeRow
		exes string
	)
	row := s.db.QueryRowContext(ctx,
		`SELECT t.id, t.host, t.agent_id, t.boot_id, t.root_pid, t.root_start_ticks, t.first_ts_ms, t.last_ts_ms, t.node_count, t.exes
		 FROM session_tree t JOIN session_node n ON n.tree_id = t.id
		 WHERE n.pid = $1 AND n.start_ticks = $2
		 ORDER BY t.id DESC LIMIT 1`, pid, startTicks)
	err := row.Scan(&id, &tr.Host, &tr.AgentID, &tr.BootID, &tr.RootPid, &tr.RootStartTicks, &tr.FirstTsMs, &tr.LastTsMs, &tr.NodeCount, &exes)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if exes != "" {
		tr.Exes = strings.Split(exes, "\x1f")
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT pid, start_ticks, parent_pid, exe, argv, first_ts_ms, last_ts_ms, exited
		 FROM session_node WHERE tree_id = $1 ORDER BY first_ts_ms, pid`, id)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var nodes []session.NodeRow
	for rows.Next() {
		var n session.NodeRow
		if err := rows.Scan(&n.Pid, &n.StartTicks, &n.ParentPid, &n.Exe, &n.Argv, &n.FirstTsMs, &n.LastTsMs, &n.Exited); err != nil {
			return nil, nil, err
		}
		nodes = append(nodes, n)
	}
	return &tr, nodes, rows.Err()
}

func (s *Store) Close() error { return s.db.Close() }
