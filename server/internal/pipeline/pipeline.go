// SPDX-License-Identifier: Apache-2.0

// Package pipeline 是事件出 ingest 去重后、进 sink 前的处理链分发点。
// Handler 逐个同步调用——需要异步的 handler 自带队列（规则/first-seen/session
// 的实现自行决定），绝不能在 Handle 里阻塞 ingest 主路径。
package pipeline

import (
	"context"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

// Handler 处理单个事件。实现必须非阻塞（快速入队即返）或自带背压。
type Handler interface {
	Name() string
	Handle(ctx context.Context, ev *pb.Event)
	Close()
}

// Pipeline 持有序 Handler。Handle 单事件逐个转发；某 handler panic 由
// 实现方保证不发生（M3 约束：handler 内部自行 recover 并计数）。
type Pipeline struct {
	handlers []Handler
}

func New(handlers ...Handler) *Pipeline {
	return &Pipeline{handlers: handlers}
}

func (p *Pipeline) Process(ctx context.Context, ev *pb.Event) {
	for _, h := range p.handlers {
		h.Handle(ctx, ev)
	}
}

// Close 逆序关闭（与 agent collector 同款语义）。
func (p *Pipeline) Close() {
	for i := len(p.handlers) - 1; i >= 0; i-- {
		p.handlers[i].Close()
	}
}

// PipelineLike 是 ingest 侧依赖的最小接口（避免包循环：ingest 不 import
// 具体实现，main 装配时注入）。
type PipelineLike interface {
	Process(ctx context.Context, ev *pb.Event)
}

// Alert 是检测层（规则/first-seen）的统一告警产物，与 CH xiezhi.alerts 表
// 与 NATS subject xiezhi.alerts 同构。RuleID 对 first-seen 形如 firstseen/<kind>。
type Alert struct {
	TsMs     int64  `json:"ts_ms"`
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"` // info/low/medium/high/critical
	Mitre    string `json:"mitre,omitempty"`
	Summary  string `json:"summary"`
	EventRef string `json:"event_ref,omitempty"` // 触发事件 JSON（截断 4KB）
}

// Sink 是告警出口（由 server 主装配注入：CH alerts 表 + NATS xiezhi.alerts）。
type Sink interface {
	EmitAlert(ctx context.Context, a *Alert)
	Close()
}
