// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeSender struct {
	mu      sync.Mutex
	batches [][]Row
	err     error
}

func (f *fakeSender) Send(_ context.Context, rows []Row) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.batches = append(f.batches, append([]Row(nil), rows...))
	return nil
}

func (f *fakeSender) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, b := range f.batches {
		n += len(b)
	}
	return n
}

func waitTotal(t *testing.T, f *fakeSender, want func(got int) bool, desc string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if want(f.total()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("sender rows = %d, want %s", f.total(), desc)
}

func TestBatcherFlushesOnBatchSize(t *testing.T) {
	f := &fakeSender{}
	b := NewBatcher(f, 1024, 3, time.Hour) // interval 不触发，只有数量触发
	b.Start()
	defer b.Close()
	for i := 0; i < 3; i++ {
		b.Add(Row{AgentID: "a"})
	}
	waitTotal(t, f, func(got int) bool { return got == 3 }, "3")
	if len(f.batches) != 1 {
		t.Fatalf("batches = %d, want single full batch", len(f.batches))
	}
}

func TestBatcherFlushesOnInterval(t *testing.T) {
	f := &fakeSender{}
	b := NewBatcher(f, 1024, 1000, 20*time.Millisecond)
	b.Start()
	defer b.Close()
	if !b.Add(Row{AgentID: "a"}) {
		t.Fatal("add failed on an empty queue")
	}
	waitTotal(t, f, func(got int) bool { return got == 1 }, "1")
}

func TestBatcherDropsWhenQueueFull(t *testing.T) {
	f := &fakeSender{}
	b := NewBatcher(f, 2, 1000, time.Hour)
	// 不 Start：无消费者，容量 2 的队列第三次 Add 必丢，结果确定
	if !b.Add(Row{AgentID: "a"}) || !b.Add(Row{AgentID: "a"}) {
		t.Fatal("queue pre-fill failed")
	}
	if b.Add(Row{AgentID: "a"}) {
		t.Fatal("third add must be dropped")
	}
	if b.Dropped() != 1 {
		t.Fatalf("dropped = %d, want 1", b.Dropped())
	}
	b.Start()
	b.Close() // 退出前排干队列，剩余 2 行必须落库
	if f.total() != 2 {
		t.Fatalf("rows sent = %d, want 2", f.total())
	}
	if b.Dropped() != 1 {
		t.Fatalf("dropped changed after close: %d", b.Dropped())
	}
}

func TestBatcherCloseFlushesRemainder(t *testing.T) {
	f := &fakeSender{}
	b := NewBatcher(f, 1024, 1000, time.Hour)
	b.Start()
	for i := 0; i < 5; i++ {
		b.Add(Row{AgentID: "a"})
	}
	b.Close()
	if f.total() != 5 {
		t.Fatalf("rows sent = %d, want 5 (Close must flush)", f.total())
	}
	if b.Dropped() != 0 {
		t.Fatalf("dropped = %d, want 0", b.Dropped())
	}
}

func TestBatcherCountsFlushFailure(t *testing.T) {
	f := &fakeSender{err: errors.New("ch down")}
	b := NewBatcher(f, 8, 2, time.Hour)
	b.Start()
	defer b.Close()
	for i := 0; i < 2; i++ {
		b.Add(Row{AgentID: "a"})
	}
	deadline := time.Now().Add(2 * time.Second)
	for b.FlushFailed() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if b.FlushFailed() != 2 {
		t.Fatalf("flushFailed = %d, want 2 (failed batch rows are counted)", b.FlushFailed())
	}
}
