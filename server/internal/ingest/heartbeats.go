// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"sort"
	"sync"
)

// Beat 是一个 agent 的最近心跳视图，供 dead-man 看门狗消费。
type Beat struct {
	AgentID    string
	Hostname   string
	InstanceID string // ECS metadata（心跳携带）；deadman 电源对账映射键，物理机为空
	LastMs     int64
}

// Heartbeats 是 ingest 侧维护的全量 agent 心跳登记：ingest 写（收到
// AGENT_HEARTBEAT 时），deadman 读（周期扫描）。只增不删——离线判定由
// staleness 驱动，条目数上界为车队规模，无需淘汰。
type Heartbeats struct {
	mu sync.RWMutex
	m  map[string]Beat
}

func NewHeartbeats() *Heartbeats {
	return &Heartbeats{m: make(map[string]Beat)}
}

// Record 带 instance_id 的登记（M3 扩展签名，ingest 心跳路径用这个）。
// 取更晚的时间戳（重放/乱序心跳不得把视图拉回过去）；hostname 以最新为准；
// instance_id 空值不覆盖旧值（metadata 偶发拿不到的轮次不能抹掉映射）。
func (h *Heartbeats) Record(agentID, hostname, instanceID string, tsMs int64) {
	if agentID == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	old, ok := h.m[agentID]
	if !ok || tsMs >= old.LastMs {
		inst := instanceID
		if inst == "" {
			inst = old.InstanceID
		}
		h.m[agentID] = Beat{AgentID: agentID, Hostname: hostname, InstanceID: inst, LastMs: tsMs}
	}
}

// Snapshot 返回按 AgentID 排序的副本，扫描方持有快照期间不受并发写影响。
func (h *Heartbeats) Snapshot() []Beat {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Beat, 0, len(h.m))
	for _, b := range h.m {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID < out[j].AgentID })
	return out
}

// Last 返回单个 agent 的最近心跳。emit 前的重查用它防止「扫描期间心跳
// 恰好到达」的误告警。
func (h *Heartbeats) Last(agentID string) (Beat, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	b, ok := h.m[agentID]
	return b, ok
}
