// SPDX-License-Identifier: Apache-2.0

package session

import "context"

// NodeRow 是归档树的一个节点行。exe/argv 在入库前（事件进树时）已消毒并
// 截断 256B，行内不再二次处理。
type NodeRow struct {
	Pid        int32
	StartTicks int64
	ParentPid  int32
	Exe        string
	Argv       string
	FirstTsMs  int64
	LastTsMs   int64
	Exited     bool
}

// TreeRow 是归档树本身（session_tree 一行）。
type TreeRow struct {
	Host           string
	AgentID        string
	BootID         string
	RootPid        int32
	RootStartTicks int64
	FirstTsMs      int64
	LastTsMs       int64
	NodeCount      int
	Exes           []string // 树内 distinct exe（调研便利 + 与 firstseen 回填对账）
}

// Store 是会话归档的持久化边界。生产实现是
// server/internal/session/pgstore（pgx，库表 session_tree/session_node）；
// 测试用内存 fake，不引真 PG。
type Store interface {
	SaveTree(ctx context.Context, t *TreeRow, nodes []NodeRow) error
	// QueryLatestTreeByPID 返回含 (host, pid) 的最近一次归档树；无则
	// (nil, nil, nil)。节点行按 (first_ts_ms, pid) 升序。
	QueryLatestTreeByPID(ctx context.Context, host string, pid int32) (*TreeRow, []NodeRow, error)
	Close() error
}
