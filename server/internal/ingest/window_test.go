// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"strconv"
	"sync"
	"testing"
)

func TestSeqWindowDuplicateDetection(t *testing.T) {
	w := newSeqWindow(8192)
	if w.Seen("a", 1) {
		t.Fatal("first sight must not be a duplicate")
	}
	if !w.Seen("a", 1) {
		t.Fatal("same agent+seq must be a duplicate")
	}
	if w.Seen("a", 2) {
		t.Fatal("a different seq must pass")
	}
}

func TestSeqWindowPerAgentNamespace(t *testing.T) {
	w := newSeqWindow(8192)
	w.Seen("a", 7)
	if w.Seen("b", 7) {
		t.Fatal("seq namespace must be per-agent")
	}
}

func TestSeqWindowEvictsOldestBeyondCapacity(t *testing.T) {
	w := newSeqWindow(4)
	for seq := uint64(1); seq <= 4; seq++ {
		w.Seen("a", seq)
	}
	if !w.Seen("a", 1) {
		t.Fatal("seq 1 must still sit inside the window")
	}
	w.Seen("a", 5)
	if !w.Seen("a", 2) {
		t.Fatal("seq 2 must still sit inside the window")
	}
	// 探测本身会回插 seq 1 并挤出 seq 2，故 2 的断言必须在前
	if w.Seen("a", 1) {
		t.Fatal("seq 1 must be evicted once the window slides past it")
	}
}

func TestSeqWindowZeroSeq(t *testing.T) {
	w := newSeqWindow(8)
	if w.Seen("a", 0) {
		t.Fatal("first seq=0 must pass")
	}
	if !w.Seen("a", 0) {
		t.Fatal("repeated seq=0 must be a duplicate")
	}
}

func TestSeqWindowConcurrentAgents(t *testing.T) {
	w := newSeqWindow(1024)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(agent string) {
			defer wg.Done()
			for seq := uint64(0); seq < 200; seq++ {
				w.Seen(agent, seq)
			}
		}("agent-" + strconv.Itoa(g))
	}
	wg.Wait()
}
