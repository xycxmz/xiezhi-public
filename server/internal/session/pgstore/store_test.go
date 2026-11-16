// SPDX-License-Identifier: Apache-2.0

package pgstore

import (
	"context"
	"os"
	"testing"

	"github.com/xycxmz/xiezhi-public/server/internal/session"
)

// 集成冒烟：默认跳过，设 XIEZHI_PG_DSN 后启用。单元行为测试在 session 包内
// 用 fake，不依赖 PG。
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("XIEZHI_PG_DSN")
	if dsn == "" {
		t.Skip("XIEZHI_PG_DSN not set")
	}
	return dsn
}

func TestSaveAndQueryLatestTree(t *testing.T) {
	s, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	t.Cleanup(func() {
		s.db.ExecContext(context.Background(), "DELETE FROM session_node WHERE tree_id IN (SELECT id FROM session_tree WHERE host = '__pgstore_test__')")
		s.db.ExecContext(context.Background(), "DELETE FROM session_tree WHERE host = '__pgstore_test__'")
		s.Close()
	})
	// 测试自含：先清残留
	if _, err := s.db.ExecContext(ctx, "DELETE FROM session_node WHERE tree_id IN (SELECT id FROM session_tree WHERE host = '__pgstore_test__')"); err != nil {
		t.Fatalf("pre-clean nodes: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM session_tree WHERE host = '__pgstore_test__'"); err != nil {
		t.Fatalf("pre-clean trees: %v", err)
	}

	save := func(rootPid int32, ts int64, nodes ...session.NodeRow) {
		t.Helper()
		row := &session.TreeRow{
			Host: "__pgstore_test__", AgentID: "ag-test", BootID: "b1",
			RootPid: rootPid, FirstTsMs: ts, LastTsMs: ts + 10,
			NodeCount: len(nodes), Exes: []string{"/bin/bash"},
		}
		if err := s.SaveTree(ctx, row, nodes); err != nil {
			t.Fatalf("save tree root=%d: %v", rootPid, err)
		}
	}

	save(10, 1000,
		session.NodeRow{Pid: 10, ParentPid: 1, Exe: "/bin/bash", FirstTsMs: 1000, LastTsMs: 1010},
		session.NodeRow{Pid: 11, ParentPid: 10, Exe: "/usr/bin/curl", Argv: "curl x", FirstTsMs: 1001, LastTsMs: 1005, Exited: true},
	)
	// 同 pid 的更晚归档必须胜出（id DESC）
	save(11, 5000,
		session.NodeRow{Pid: 11, ParentPid: 1, Exe: "/bin/sh", FirstTsMs: 5000, LastTsMs: 5010},
	)

	tr, nodes, err := s.QueryLatestTreeByPID(ctx, "__pgstore_test__", 11)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if tr == nil || len(nodes) != 1 {
		t.Fatalf("latest tree = %+v nodes=%d, want the ts=5000 single-node tree", tr, len(nodes))
	}
	if nodes[0].Pid != 11 || nodes[0].Exe != "/bin/sh" || nodes[0].FirstTsMs != 5000 {
		t.Errorf("node = %+v", nodes[0])
	}

	// 未命中
	tr, nodes, err = s.QueryLatestTreeByPID(ctx, "__pgstore_test__", 4242)
	if err != nil || tr != nil || nodes != nil {
		t.Fatalf("miss = %v/%v/%v, want nils", tr, nodes, err)
	}

	// 大树分块写入（>nodeChunk 行）往返无损：根 + 1200 子孙
	var big []session.NodeRow
	big = append(big, session.NodeRow{Pid: 9000, Exe: "/x", FirstTsMs: 1, LastTsMs: 1})
	for i := int32(1); i <= 1200; i++ {
		big = append(big, session.NodeRow{Pid: 9000 + i, ParentPid: 9000 + i - 1, Exe: "/x", FirstTsMs: int64(i), LastTsMs: int64(i)})
	}
	save(9000, 1, big...)
	_, nodes, err = s.QueryLatestTreeByPID(ctx, "__pgstore_test__", 9000+1200)
	if err != nil {
		t.Fatalf("query big: %v", err)
	}
	if len(nodes) != 1201 {
		t.Errorf("big tree roundtrip = %d nodes, want 1201", len(nodes))
	}
}
