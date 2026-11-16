// SPDX-License-Identifier: Apache-2.0

package deadman

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/xycxmz/xiezhi-public/server/internal/ingest"
)

type fakeHBStore struct {
	mu       sync.Mutex
	rows     []ingest.Beat // LoadBeats 的固定返回
	upserts  [][]ingest.Beat
	closed   bool
	failLoad error
}

func (f *fakeHBStore) UpsertBeats(_ context.Context, beats []ingest.Beat) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upserts = append(f.upserts, append([]ingest.Beat(nil), beats...))
	return nil
}

func (f *fakeHBStore) LoadBeats(_ context.Context) ([]ingest.Beat, error) {
	if f.failLoad != nil {
		return nil, f.failLoad
	}
	return append([]ingest.Beat(nil), f.rows...), nil
}

func (f *fakeHBStore) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeHBStore) upsertCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.upserts)
}

func waitForPersist(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within deadline")
		}
		time.Sleep(time.Millisecond)
	}
}

// 回灌乱序防护：内存已有的更新视图不被 PG 旧行回拨；空 instance 不抹映射。
func TestLoadIntoKeepsNewestMemoryState(t *testing.T) {
	hb := ingest.NewHeartbeats()
	hb.Record("a", "h1", "i1", 5000)
	st := &fakeHBStore{rows: []ingest.Beat{
		{AgentID: "a", Hostname: "h-old", InstanceID: "i-old", LastMs: 3000}, // 滞后行：整体忽略
		{AgentID: "a", Hostname: "h2", InstanceID: "", LastMs: 9000},         // 更新但 instance 空
		{AgentID: "b", Hostname: "hb", InstanceID: "ib", LastMs: 100},        // 新 agent 全收
	}}
	if err := loadInto(context.Background(), hb, st); err != nil {
		t.Fatalf("loadInto: %v", err)
	}
	a, ok := hb.Last("a")
	if !ok || a.Hostname != "h2" || a.InstanceID != "i1" || a.LastMs != 9000 {
		t.Fatalf("agent a = %+v, want h2/i1/9000 (no rewind, instance kept)", a)
	}
	b, ok := hb.Last("b")
	if !ok || b.LastMs != 100 {
		t.Fatalf("agent b = %+v, want restored", b)
	}
}

func TestLoadIntoStoreErrorPropagates(t *testing.T) {
	st := &fakeHBStore{failLoad: context.DeadlineExceeded}
	if _, err := attachPersist(ingest.NewHeartbeats(), st, time.Second); err == nil {
		t.Fatal("load failure must abort attach")
	}
}

func TestAttachPersistLoadsThenSavesSnapshots(t *testing.T) {
	st := &fakeHBStore{rows: []ingest.Beat{
		{AgentID: "a", Hostname: "h1", InstanceID: "i1", LastMs: 100},
	}}
	hb := ingest.NewHeartbeats()
	stop, err := attachPersist(hb, st, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	// 回灌在返回前同步完成：看门狗随后起跑即有视野
	if _, ok := hb.Last("a"); !ok {
		t.Fatal("beat not restored before attach returned")
	}

	hb.Record("b", "h2", "", 200)
	waitForPersist(t, func() bool { return st.upsertCount() >= 1 })
	st.mu.Lock()
	last := st.upserts[len(st.upserts)-1]
	st.mu.Unlock()
	if len(last) != 2 {
		t.Fatalf("snapshot upsert = %d beats, want full snapshot of 2", len(last))
	}

	stop()
	if !st.closed {
		t.Fatal("stop must close store")
	}
	n := st.upsertCount()
	stop() // 幂等
	if st.upsertCount() != n {
		t.Fatal("second stop must not trigger more work")
	}
}

// 集成冒烟：设 XIEZHI_PG_DSN 后启用（项目 env-gated 测试惯例）。验证真实 SQL
// 的建表/upsert/回灌闭环；测试键带 __deadman_test__ 前缀，结束即清。
func TestPersistRoundtripPG(t *testing.T) {
	dsn := os.Getenv("XIEZHI_PG_DSN")
	if dsn == "" {
		t.Skip("XIEZHI_PG_DSN not set")
	}
	ctx := context.Background()
	st, err := openHBStore(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		st.db.ExecContext(context.Background(), "DELETE FROM heartbeat_state WHERE agent_id LIKE '__deadman_test__%'")
		st.Close()
	})
	if _, err := st.db.ExecContext(ctx, "DELETE FROM heartbeat_state WHERE agent_id LIKE '__deadman_test__%'"); err != nil {
		t.Fatalf("pre-clean: %v", err)
	}

	hb := ingest.NewHeartbeats()
	hb.Record("__deadman_test__a", "h1", "i1", 1000)
	hb.Record("__deadman_test__b", "h2", "", 2000)
	if err := st.UpsertBeats(ctx, hb.Snapshot()); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// 幂等：同快照重放不报错不变形
	if err := st.UpsertBeats(ctx, hb.Snapshot()); err != nil {
		t.Fatalf("idempotent upsert: %v", err)
	}

	hb2 := ingest.NewHeartbeats()
	if err := loadInto(ctx, hb2, st); err != nil {
		t.Fatalf("load: %v", err)
	}
	a, ok := hb2.Last("__deadman_test__a")
	if !ok || a.LastMs != 1000 || a.InstanceID != "i1" || a.Hostname != "h1" {
		t.Fatalf("restored a = %+v", a)
	}
	if _, ok := hb2.Last("__deadman_test__b"); !ok {
		t.Fatal("restored b missing")
	}
}
