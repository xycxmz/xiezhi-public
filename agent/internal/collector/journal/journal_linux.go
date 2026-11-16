// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package journal 是认证日志采集器（M2）：tail 文件（默认 /var/log/auth.log，
// 轮转感知），解析 sshd/sudo/su/cron 行为 JOURNAL_AUTH 事件。journald 模式
// （journalctl 跟随）留 M3；rsyslog 未装的环境 New 返回明确错误，agent 降
// 级是可接受结局。公共头由 runtime 富化。
package journal

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

const (
	defaultPath       = "/var/log/auth.log"
	defaultInterval   = time.Second
	defaultStartLines = 100
	chanBuffer        = 1024
	// skipLogEvery：解析失败行的告警节流，否则攻击者刷垃圾行能把日志打爆。
	skipLogEvery = 1000
	// pollLogEvery：poll 错误重试期间的告警节流（默认 interval 1s 即约每分钟一条）。
	pollLogEvery = 60
)

// Collector 实现 collector.Collector。
type Collector struct {
	events     chan *pb.Event
	log        *slog.Logger
	path       string
	interval   time.Duration
	startLines int

	skipped   uint64 // 认了行但出不了事件的计数（含 sshd 连接噪声等）
	pollFails uint64 // 连续 poll 失败计数（成功即清零）
}

// New 构造采集器；path 为空用默认 /var/log/auth.log。文件不存在/不可读
// 返回明确错误——调用方（main）据此跳过本采集器并降级。
func New(path string) (*Collector, error) {
	if path == "" {
		path = defaultPath
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("journal: auth log %q unreadable: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("journal: %s: not a regular file", path)
	}
	return &Collector{
		events:     make(chan *pb.Event, chanBuffer),
		log:        slog.With("collector", "journal"),
		path:       path,
		interval:   defaultInterval,
		startLines: defaultStartLines,
	}, nil
}

func (c *Collector) Name() string             { return "journal" }
func (c *Collector) Events() <-chan *pb.Event { return c.events }

// Run 阻塞运行：首轮从文件末尾 -startLines 行起投递，之后每 interval 轮询
// 增量。ctx 取消后关闭事件通道并返回。
func (c *Collector) Run(ctx context.Context) error {
	defer close(c.events)
	t := newTailer(c.path, c.startLines)
	defer t.close()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		lines, err := t.poll()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// 瞬时 IO/权限故障只记日志（节流）等下轮重试：一次错误即退出
			// 会让认证日志通道静默死亡直到 agent 重启。
			c.pollFails++
			if c.pollFails == 1 || c.pollFails%pollLogEvery == 0 {
				c.log.Warn("auth log poll failed, will retry", "err", err, "consecutive_failures", c.pollFails)
			}
		} else {
			c.pollFails = 0
			for _, line := range lines {
				ev := ParseLine(line)
				if ev == nil {
					c.skipped++
					if c.skipped%skipLogEvery == 0 {
						c.log.Warn("unparsed auth lines so far", "skipped", c.skipped)
					}
					continue
				}
				select {
				case c.events <- &pb.Event{
					Header: &pb.EventHeader{EventType: pb.EventType_JOURNAL_AUTH},
					Body:   &pb.Event_JournalAuth{JournalAuth: ev},
				}:
				case <-ctx.Done():
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Close 无跨 Run 资源（tailer 句柄由 Run 的 defer 释放）。
func (c *Collector) Close() {}
