// SPDX-License-Identifier: Apache-2.0

package pgstore

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/xycxmz/xiezhi-public/server/internal/firstseen"
)

// 集成冒烟：默认跳过，设 XIEZHI_PG_DSN 后启用（项目 env-gated 测试惯例）。
// 单元行为测试在 firstseen 包内用 fake，不依赖 PG。
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("XIEZHI_PG_DSN")
	if dsn == "" {
		t.Skip("XIEZHI_PG_DSN not set")
	}
	return dsn
}

func obs(key string, ts int64, count int) firstseen.Obs {
	return firstseen.Obs{Key: key, Kind: "exe", Host: "__pgstore_test__", AgentID: "ag-test", TsMs: ts, Count: count}
}

func TestUpsertXmaxNewDetection(t *testing.T) {
	dsn := testDSN(t)
	s, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	t.Cleanup(func() {
		s.db.ExecContext(context.Background(), "DELETE FROM first_seen WHERE key LIKE '__pgstore_test__/%'")
		s.Close()
	})

	k1 := "__pgstore_test__/k1"
	k2 := "__pgstore_test__/k2"
	k3 := "__pgstore_test__/k3"
	// 测试自含：先清残留
	if _, err := s.db.ExecContext(ctx, "DELETE FROM first_seen WHERE key LIKE '__pgstore_test__/%'"); err != nil {
		t.Fatalf("pre-clean: %v", err)
	}

	// 首批：两个都新
	idx, err := s.Upsert(ctx, []firstseen.Obs{obs(k1, 1000, 1), obs(k2, 1000, 1)})
	if err != nil {
		t.Fatalf("upsert1: %v", err)
	}
	if len(idx) != 2 {
		t.Fatalf("first upsert new = %v, want both", idx)
	}
	// 复现批次：无新键
	idx, err = s.Upsert(ctx, []firstseen.Obs{obs(k1, 2000, 3), obs(k2, 2000, 1)})
	if err != nil {
		t.Fatalf("upsert2: %v", err)
	}
	if len(idx) != 0 {
		t.Fatalf("repeat upsert new = %v, want none", idx)
	}
	// 混批：只有 k3 新
	idx, err = s.Upsert(ctx, []firstseen.Obs{obs(k2, 3000, 1), obs(k3, 3000, 1)})
	if err != nil {
		t.Fatalf("upsert3: %v", err)
	}
	if len(idx) != 1 {
		t.Fatalf("mixed upsert new = %v, want [k3]", idx)
	}

	// hit_count/last_ts/first_ts 落库正确性（k1：两次 upsert，count 1+3）
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var firstTs, lastTs, hits int64
	if err := db.QueryRowContext(ctx,
		"SELECT first_ts, last_ts, hit_count FROM first_seen WHERE key = $1", k1).Scan(&firstTs, &lastTs, &hits); err != nil {
		t.Fatalf("select k1: %v", err)
	}
	if firstTs != 1000 || lastTs != 2000 || hits != 4 {
		t.Errorf("k1 first=%d last=%d hits=%d, want 1000/2000/4", firstTs, lastTs, hits)
	}
}
