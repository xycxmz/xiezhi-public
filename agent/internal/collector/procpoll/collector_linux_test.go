// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procpoll

import (
	"context"
	"strconv"
	"testing"
	"time"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

func newTestCollector(scanFn func() snapshot, maxProcs int) *Collector {
	c := &Collector{
		events:   make(chan *pb.Event, 64),
		log:      testLogger(),
		interval: 5 * time.Millisecond,
		maxProcs: maxProcs,
	}
	c.scanFn = scanFn
	return c
}

func recvEvent(t *testing.T, ch <-chan *pb.Event) *pb.Event {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("events channel closed unexpectedly")
		}
		return ev
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for event")
		return nil
	}
}

// Run 行为：首轮基线全量 appeared，次轮只报新增；事件带 comm/exe/detail。
func TestRunEmitsBaselineThenNewProcess(t *testing.T) {
	rounds := []snapshot{
		{1: {Pid: 1, Comm: "systemd", StartTicks: 10, Exe: "/usr/lib/systemd/systemd"}},
		{
			1: {Pid: 1, Comm: "systemd", StartTicks: 10, Exe: "/usr/lib/systemd/systemd"},
			2: {Pid: 2, Comm: "kthreadd", StartTicks: 20},
		},
	}
	idx := -1
	c := newTestCollector(func() snapshot {
		idx++
		if idx >= len(rounds) {
			return rounds[len(rounds)-1]
		}
		return rounds[idx]
	}, maxProcs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	ev1 := recvEvent(t, c.events)
	if ev1.Header.EventType != pb.EventType_PROC_DIFF {
		t.Fatalf("event type = %v, want PROC_DIFF", ev1.Header.EventType)
	}
	d := ev1.GetProcDiff()
	if d.Kind != "appeared_process" || len(d.Pids) != 1 || d.Pids[0] != "1" {
		t.Errorf("baseline event = %+v, want appeared_process pid 1", d)
	}
	if d.Detail == "" {
		t.Error("detail empty, want reconciliation data-plane note with comm/exe")
	}

	ev2 := recvEvent(t, c.events)
	d2 := ev2.GetProcDiff()
	if len(d2.Pids) != 1 || d2.Pids[0] != "2" {
		t.Errorf("second-round event pids = %v, want [2]", d2.Pids)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
	if _, ok := <-c.events; ok {
		t.Error("events channel not closed after Run returned")
	}
}

// 超限轮（容器风暴）：不投递、不更新基线；下轮恢复后不产生全量洪水。
func TestRunSkipsRoundOverLimit(t *testing.T) {
	steady := snapshot{1: {Pid: 1, StartTicks: 10}}
	storm := make(snapshot, 50)
	for pid := uint32(1); pid <= 50; pid++ {
		storm[pid] = procEntry{Pid: pid, StartTicks: uint64(pid)}
	}
	rounds := []snapshot{steady, storm, steady}
	idx := -1
	c := newTestCollector(func() snapshot {
		idx++
		if idx >= len(rounds) {
			return steady
		}
		return rounds[idx]
	}, 49)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	// 首轮基线 1 条事件；第二轮 50 > 50 上限被跳过；第三轮 steady 无 diff。
	recvEvent(t, c.events)
	time.Sleep(50 * time.Millisecond)

	select {
	case ev, ok := <-c.events:
		if ok {
			t.Errorf("unexpected event during storm-skip rounds: %+v", ev.GetProcDiff())
		} else {
			t.Fatal("events channel closed while Run should be alive")
		}
	default:
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

// PID 复用：同 pid 新 ticks 走 appeared，pids 字段携带单 pid。
func TestRunPidReuseAppeared(t *testing.T) {
	rounds := []snapshot{
		{42: {Pid: 42, Comm: "old", StartTicks: 100}},
		{42: {Pid: 42, Comm: "curl", StartTicks: 900, Exe: "/usr/bin/curl"}},
	}
	idx := -1
	c := newTestCollector(func() snapshot {
		idx++
		if idx >= len(rounds) {
			return rounds[len(rounds)-1]
		}
		return rounds[idx]
	}, maxProcs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	for i := 0; i < 2; i++ {
		ev := recvEvent(t, c.events)
		d := ev.GetProcDiff()
		if len(d.Pids) != 1 || d.Pids[0] != strconv.Itoa(42) {
			t.Errorf("event %d pids = %v, want [42]", i, d.Pids)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

// New 在 /proc 存在的 Linux 上可用，interval<=0 归一到默认值。
func TestNewDefaults(t *testing.T) {
	c, err := New(0)
	if err != nil {
		t.Fatalf("New(0) err = %v, want nil on linux", err)
	}
	defer c.Close()
	if c.Name() != "procpoll" {
		t.Errorf("Name = %q, want procpoll", c.Name())
	}
	if c.interval != defaultInterval {
		t.Errorf("interval = %v, want %v", c.interval, defaultInterval)
	}
	if c.scanFn == nil {
		t.Error("scanFn not wired")
	}
}
