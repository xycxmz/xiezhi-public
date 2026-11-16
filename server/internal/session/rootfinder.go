// SPDX-License-Identifier: Apache-2.0

package session

import (
	"strings"
	"sync"
	"time"
)

// SessionRoot identifies the root of a process's session tree.
// Used by intent layer for bucket key upgrade (R4.3).
type SessionRoot struct {
	RootPid   int32
	RootTicks uint64
	RootExe   string
}

// RootFinder maps a process to its session tree root (R4.3).
// Implementations must be non-blocking (or return quickly).
type RootFinder interface {
	FindRoot(host string, pid int32) (SessionRoot, bool)
}

// sessionRootFinder adapts Handler to RootFinder (lock-guarded read).
// This is the session package's export point for R4.3 bucket key upgrade.
type sessionRootFinder struct{ h *Handler }

func (h *Handler) RootFinder() RootFinder { return sessionRootFinder{h: h} }

func (s sessionRootFinder) FindRoot(host string, pid int32) (SessionRoot, bool) {
	s.h.mu.Lock()
	defer s.h.mu.Unlock()

	ht, ok := s.h.hosts[host]
	if !ok {
		return SessionRoot{}, false
	}

	node, ok := ht.byPid[uint32(pid)]
	if !ok || node == nil {
		// 短命进程竞态（线上实测）：EXECVE 刚入 intent 异步队列、EXIT 已把
		// 节点摘出活索引。墓园化身树链完整（归档时才清索引），与 fork 的
		// parent 查找（tree.go）同一回落取舍。
		node, ok = ht.lastByPid[uint32(pid)]
		if !ok || node == nil {
			return SessionRoot{}, false
		}
	}

	// Walk up to the first entity process: fork-built placeholder anchors
	// have no exec (exe==""), and crossing them merges unrelated sessions
	// (sshd/systemd placeholders span every connection/service) into one
	// bucket tree — measured as benchmark round 3/4 co-bucket suppression.
	// Stopping at the last exec'd ancestor keys buckets per real shell
	// session; sudo/setuid chains within one shell still share the bucket.
	root := node
	for root.parent != nil && root.parent.exe != "" {
		root = root.parent
	}

	return SessionRoot{
		RootPid:   int32(root.pid),
		RootTicks: root.startTicks,
		RootExe:   root.exe,
	}, true
}

// ensure sync import is used
var _ sync.Mutex
var _ = strings.TrimSpace
var _ = time.Now
