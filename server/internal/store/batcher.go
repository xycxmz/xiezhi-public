// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// Batcher 在独立 goroutine 里聚合 Row：满 maxRows 或每 interval 强制投递。
// Add 永不阻塞（队列满即丢弃计数），存储侧故障不反压 ingest。
type Batcher struct {
	queue    chan Row
	sender   RowSender
	maxRows  int
	interval time.Duration

	dropped     atomic.Uint64
	flushFailed atomic.Uint64

	stop chan struct{}
	done chan struct{}
}

func NewBatcher(sender RowSender, queueSize, maxRows int, interval time.Duration) *Batcher {
	return &Batcher{
		queue:    make(chan Row, queueSize),
		sender:   sender,
		maxRows:  maxRows,
		interval: interval,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func (b *Batcher) Start() { go b.loop() }

// Add 入队一行；false 表示队列满被丢弃。
func (b *Batcher) Add(r Row) bool {
	select {
	case b.queue <- r:
		return true
	default:
		b.dropped.Add(1)
		return false
	}
}

func (b *Batcher) Dropped() uint64     { return b.dropped.Load() }
func (b *Batcher) FlushFailed() uint64 { return b.flushFailed.Load() }

// Close 停止聚合，排干队列并投递剩余行后返回（退出前的最终 flush）。
func (b *Batcher) Close() {
	close(b.stop)
	<-b.done
}

func (b *Batcher) loop() {
	defer close(b.done)
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	buf := make([]Row, 0, b.maxRows)
	for {
		select {
		case r := <-b.queue:
			buf = append(buf, r)
			if len(buf) >= b.maxRows {
				b.flush(&buf)
			}
		case <-ticker.C:
			b.flush(&buf)
		case <-b.stop:
			for {
				select {
				case r := <-b.queue:
					buf = append(buf, r)
				default:
					b.flush(&buf)
					return
				}
			}
		}
	}
}

// flush 超时钳制在 sendTimeout：Send 卡死不能拖住聚合循环与退出流程。
func (b *Batcher) flush(buf *[]Row) {
	if len(*buf) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := b.sender.Send(ctx, *buf); err != nil {
		b.flushFailed.Add(uint64(len(*buf)))
		slog.Error("clickhouse flush failed, batch discarded", "rows", len(*buf), "err", err)
	}
	*buf = (*buf)[:0]
}
