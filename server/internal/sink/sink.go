// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"log/slog"

	"github.com/xycxmz/xiezhi-public/server/internal/store"
)

// Publisher 是 NATS 发布端的最小面；*nats.Conn 直接满足它。
type Publisher interface {
	Publish(subj string, data []byte) error
}

// DualWrite 双写：先 NATS（尽力而为，失败仅记日志），再入 CH 批量队列
// （满即丢并计数）。两路都不阻塞调用方，ingest 永不被存储侧卡住。
type DualWrite struct {
	pub     Publisher
	subject string
	batcher *store.Batcher
}

func NewDualWrite(pub Publisher, subject string, batcher *store.Batcher) *DualWrite {
	return &DualWrite{pub: pub, subject: subject, batcher: batcher}
}

// Write 的 NATS 负载即事件 JSON 全文（Body），与 CH body 列同源。
func (d *DualWrite) Write(row store.Row) {
	if err := d.pub.Publish(d.subject, []byte(row.Body)); err != nil {
		slog.Warn("nats publish failed", "subject", d.subject, "err", err)
	}
	// 丢弃已由 batcher.Dropped() 计数，此处不重复记日志避免刷屏
	_ = d.batcher.Add(row)
}
