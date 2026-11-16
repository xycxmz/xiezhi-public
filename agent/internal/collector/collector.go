// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

// Collector 是采集器契约（agent 运行时与具体实现之间的唯一边界）。
// 实现负责产出事件体（event_type + body + 自身可知字段），公共头（seq/agent_id/
// boot_id/kernel/cgroup 等）由 agent 运行时统一富化，保证 seq 单调与口径一致。
type Collector interface {
	// Name 返回采集器标识（用于日志、心跳 collector_mode 字段）。
	Name() string

	// Run 阻塞运行直到 ctx 取消。事件经 Events() 通道投递；通道由实现创建并拥有，
	// 容量建议 >= 1024；ctx 取消后实现须关闭通道并返回。
	Run(ctx context.Context) error

	// Events 返回事件输出通道。实现投递不得阻塞超过 ctx 生命周期（select ctx.Done）。
	Events() <-chan *pb.Event

	// Close 释放资源（eBPF 程序/driver 设备等）。Run 返回后调用一次。
	Close()
}
