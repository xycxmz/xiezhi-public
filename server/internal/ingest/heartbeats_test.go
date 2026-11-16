// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"fmt"
	"sync"
	"testing"
)

func TestHeartbeatsRecordSemantics(t *testing.T) {
	h := NewHeartbeats()
	h.Record("a", "h1", "", 1000)
	h.Record("a", "h2", "", 500) // 乱序/重放不得回拨
	if b, _ := h.Last("a"); b.LastMs != 1000 || b.Hostname != "h1" {
		t.Fatalf("older replay overwrote view: %+v", b)
	}
	h.Record("a", "h3", "", 1000) // 同 ts 的重复心跳仍更新 hostname
	if b, _ := h.Last("a"); b.Hostname != "h3" {
		t.Fatalf("same-ts heartbeat should refresh hostname: %+v", b)
	}
	h.Record("", "x", "", 1) // 空 agent_id 不入表
	if got := len(h.Snapshot()); got != 1 {
		t.Fatalf("snapshot size = %d, want 1", got)
	}
	if _, ok := h.Last("missing"); ok {
		t.Fatal("missing agent must not be found")
	}
}

func TestHeartbeatsSnapshotSortedCopy(t *testing.T) {
	h := NewHeartbeats()
	for _, id := range []string{"c", "a", "b"} {
		h.Record(id, "h", "", 1)
	}
	snap := h.Snapshot()
	if snap[0].AgentID != "a" || snap[1].AgentID != "b" || snap[2].AgentID != "c" {
		t.Fatalf("snapshot not sorted: %+v", snap)
	}
	snap[0].Hostname = "mutated"
	if b, _ := h.Last("a"); b.Hostname != "h" {
		t.Fatal("snapshot must be a copy, mutating it leaked into the registry")
	}
}

// -race 复跑的目标：Record 与 Snapshot/Last 并发读写。
func TestHeartbeatsConcurrentRecord(t *testing.T) {
	h := NewHeartbeats()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				h.Record(fmt.Sprintf("agent-%d", w), "h", "", int64(i))
				_ = h.Snapshot()
				h.Last("agent-0")
			}
		}(w)
	}
	wg.Wait()
	if got := len(h.Snapshot()); got != 8 {
		t.Fatalf("registered = %d, want 8", got)
	}
}
