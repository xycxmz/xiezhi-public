// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package procpoll 是 /proc 轮询采集器（M2）：周期扫 /proc 快照，与上一轮
// diff 出现/消失，把 appeared 打成 PROC_DIFF 事件。它是三通道对账的
// /proc 侧数据面：隐藏进程判定（/proc 有而内核事件流无，或反向）
// 在 M3 会话层做，本包只保证快照 diff 可靠。
package procpoll

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

const (
	defaultInterval = 10 * time.Second
	// maxProcs 防容器风暴：进程数超限时丢本轮快照（保留上轮状态，避免下轮
	// 全量 appeared 洪水），记 warn 等下轮。
	maxProcs   = 50000
	detailMax  = 2048
	chanBuffer = 1024
)

// Collector 实现 collector.Collector。
type Collector struct {
	events   chan *pb.Event
	log      *slog.Logger
	interval time.Duration
	maxProcs int

	// 接缝（默认扫真实 /proc，测试注入假件）
	scanFn func() snapshot
}

// New 构造采集器；interval <= 0 用默认 10s（对账轮询建议 5-30s）。
// /proc 不可读时返回明确错误，调用方降级。
func New(interval time.Duration) (*Collector, error) {
	if interval <= 0 {
		interval = defaultInterval
	}
	if fi, err := os.Stat("/proc"); err != nil {
		return nil, fmt.Errorf("procpoll: /proc unreadable: %w", err)
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("procpoll: /proc: not a directory")
	}
	c := &Collector{
		events:   make(chan *pb.Event, chanBuffer),
		log:      slog.With("collector", "procpoll"),
		interval: interval,
		maxProcs: maxProcs,
	}
	c.scanFn = func() snapshot { return scan("/proc") }
	return c, nil
}

func (c *Collector) Name() string             { return "procpoll" }
func (c *Collector) Events() <-chan *pb.Event { return c.events }

// Run 阻塞运行：每轮扫描→限流检查→diff→投递。首轮 prev 为空，全量进程以
// appeared_process 上报一次（这是对账层需要的基线清单）。ctx 取消后关闭
// 事件通道并返回。
func (c *Collector) Run(ctx context.Context) error {
	defer close(c.events)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	var prev snapshot
	for {
		cur := c.scanFn()
		switch {
		case cur == nil:
			// /proc 读目录失败（挂载点异常）：保留上轮状态，下轮重试
			c.log.Warn("scan returned no snapshot, keeping previous state")
		case len(cur) > c.maxProcs:
			c.log.Warn("process count over limit, round skipped", "count", len(cur), "limit", c.maxProcs)
		default:
			for _, pid := range diffAppeared(prev, cur) {
				select {
				case c.events <- appearedEvent(cur, pid):
				case <-ctx.Done():
					return nil
				}
			}
			prev = cur
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// appearedEvent 把单条新进程打成事件；pids 只放本条 pid，comm/exe/父进程进
// Detail，让消费方不用回查 /proc 也能初判。
func appearedEvent(cur snapshot, pid uint32) *pb.Event {
	e := cur[pid]
	detail := fmt.Sprintf("proc-poll snapshot diff (reconciliation data plane; hidden-process verdict is M3 session layer) pid=%d comm=%s ppid=%d start_ticks=%d exe=%s",
		pid, e.Comm, e.Ppid, e.StartTicks, e.Exe)
	if len(detail) > detailMax {
		detail = detail[:detailMax]
	}
	return &pb.Event{
		Header: &pb.EventHeader{EventType: pb.EventType_PROC_DIFF},
		Body: &pb.Event_ProcDiff{ProcDiff: &pb.ProcDiffEvent{
			Kind:   "appeared_process",
			Pids:   []string{strconv.FormatUint(uint64(pid), 10)},
			Detail: detail,
		}},
	}
}

// Close 无内核资源，no-op（满足 collector.Collector 契约）。
func (c *Collector) Close() {}
