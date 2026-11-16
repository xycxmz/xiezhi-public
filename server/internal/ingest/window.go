// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"log"
	"sync"
)

// seqWindow 按 agent 记录最近 capacity 个 seq，用于断线重放去重。
// 窗口有界：超出容量的最老 seq 被挤出，极度迟到的旧重放会被再次接受
// （M1 用内存窗口，PG 持久化对账在后续里程碑）。
type seqWindow struct {
	mu       sync.Mutex
	capacity int
	agents   map[string]*agentSeqs
}

type agentSeqs struct {
	seen  map[uint64]struct{}
	order []uint64 // FIFO，仅用于挤出最老 seq；append 摊还后内存 O(capacity)
}

func newSeqWindow(capacity int) *seqWindow {
	return &seqWindow{capacity: capacity, agents: make(map[string]*agentSeqs)}
}

// maxAgents 是 distinct agent_id 硬上限（F-003/R8.4 审计）：agent_id 是
// 事件头自报字段，无上限开桶可被随机 id 流打爆内存（每桶还预分配
// capacity 大 map）。超限时拒收（返回 true 视作重复丢弃）并大声告警。
const maxAgents = 4096

// Seen 记录 seq 并报告是否已在窗口内：true=重复，false=首次。
func (w *seqWindow) Seen(agentID string, seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	a := w.agents[agentID]
	if a == nil {
		if len(w.agents) >= maxAgents {
			log.Printf("ingest: agent id cardinality cap %d hit, rejecting unknown agent %q", maxAgents, agentID)
			return true
		}
		a = &agentSeqs{seen: make(map[uint64]struct{}, w.capacity)}
		w.agents[agentID] = a
	}
	if _, dup := a.seen[seq]; dup {
		return true
	}
	a.seen[seq] = struct{}{}
	a.order = append(a.order, seq)
	if len(a.order) > w.capacity {
		delete(a.seen, a.order[0])
		a.order = a.order[1:]
	}
	return false
}
