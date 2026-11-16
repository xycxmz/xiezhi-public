// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/xycxmz/xiezhi-public/proto"

	"github.com/xycxmz/xiezhi-public/agent/internal/collector"
	"github.com/xycxmz/xiezhi-public/agent/internal/config"
	"github.com/xycxmz/xiezhi-public/agent/internal/identity"
)

type fakeSink struct {
	in    chan *pb.Event
	spool atomic.Uint64
}

func (s *fakeSink) In() chan *pb.Event { return s.in }
func (s *fakeSink) SpoolBytes() uint64 { return s.spool.Load() }

// t 每例独立隔离 seq/spool 落盘路径：不设 SpoolDir 时 seqPath 会落到
// 包目录的真实 seq 文件，跨测试运行泄漏水位（R8.4 复核发现）。
func newRuntime(t *testing.T, sink *fakeSink, collectors ...*mockCollector) *Runtime {
	t.Helper()
	cfg := &config.Config{HeartbeatIntervalSec: 3600, SpoolDir: filepath.Join(t.TempDir(), "spool")}
	id := &identity.Identity{AgentID: "agent-1", Hostname: "host-1", BootID: "boot-1", Kernel: "5.10.0"}
	cs := make([]collector.Collector, len(collectors))
	for i, c := range collectors {
		cs[i] = c
	}
	return New(cfg, id, sink, "test-version", cs...)
}

func runAndStop(t *testing.T, rt *Runtime, waitAll <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rt.Run(ctx); close(done) }()
	if waitAll != nil {
		<-waitAll
	}
	cancel()
	<-done
}

// allEmitted 返回全部 mock 投递完毕后关闭的通道。
func allEmitted(mcs ...*mockCollector) <-chan struct{} {
	var wg sync.WaitGroup
	for _, mc := range mcs {
		wg.Add(1)
		go func(c *mockCollector) { <-c.emitted; wg.Done() }(mc)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	return done
}

func TestEnrichSingleCollectorStrictSeqOrder(t *testing.T) {
	sink := &fakeSink{in: make(chan *pb.Event, 256)}
	mc := newMockCollector("ebpf", 50)
	rt := newRuntime(t, sink, mc)
	runAndStop(t, rt, allEmitted(mc))

	if got := len(sink.in); got != 50 {
		t.Fatalf("sink holds %d events, want 50", got)
	}
	for i := 1; i <= 50; i++ {
		ev := <-sink.in
		h := ev.Header
		if h.Seq != uint64(i) {
			t.Fatalf("event %d: seq = %d (delivery must be strictly increasing for a single pump)", i, h.Seq)
		}
		if h.AgentId != "agent-1" || h.Hostname != "host-1" || h.BootId != "boot-1" || h.Kernel != "5.10.0" {
			t.Fatalf("event %d: header not enriched: %+v", i, h)
		}
		if h.TsMs == 0 {
			t.Fatalf("event %d: ts_ms not set", i)
		}
		if h.EventType != pb.EventType_EXECVE {
			t.Fatalf("event %d: event_type overwritten by runtime: %v", i, h.EventType)
		}
		if ev.GetExit() == nil {
			t.Fatalf("event %d: body lost", i)
		}
	}
	if sent, dropped := rt.Stats(); sent != 50 || dropped != 0 {
		t.Fatalf("stats sent=%d dropped=%d, want 50/0", sent, dropped)
	}
}

func TestConcurrentCollectorsSeqUnique(t *testing.T) {
	sink := &fakeSink{in: make(chan *pb.Event, 4096)}
	const per, nCollectors = 100, 3
	mcs := []*mockCollector{newMockCollector("a", per), newMockCollector("b", per), newMockCollector("c", per)}
	rt := newRuntime(t, sink, mcs...)
	runAndStop(t, rt, allEmitted(mcs...))

	total := per * nCollectors
	seen := make(map[uint64]bool, total)
	for len(sink.in) > 0 || len(seen) < total {
		select {
		case ev := <-sink.in:
			if seen[ev.Header.Seq] {
				t.Fatalf("duplicate seq %d across collectors", ev.Header.Seq)
			}
			seen[ev.Header.Seq] = true
		default:
			time.Sleep(time.Millisecond)
		}
	}
	for i := uint64(1); i <= uint64(total); i++ {
		if !seen[i] {
			t.Fatalf("seq %d missing (seqs must be a permutation of 1..%d)", i, total)
		}
	}
}

func TestDropWhenSinkFull(t *testing.T) {
	sink := &fakeSink{in: make(chan *pb.Event, 4)}
	mc := newMockCollector("ebpf", 100)
	rt := newRuntime(t, sink, mc)
	runAndStop(t, rt, allEmitted(mc))

	sent, dropped := rt.Stats()
	if sent > 4 {
		t.Fatalf("sent = %d, must not exceed sink capacity 4", sent)
	}
	if sent+dropped != 100 {
		t.Fatalf("sent+dropped = %d+%d, want 100 total", sent, dropped)
	}
}

func TestHeartbeatEmitted(t *testing.T) {
	sink := &fakeSink{in: make(chan *pb.Event, 64)}
	rt := newRuntime(t, sink)
	rt.heartbeatTick = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rt.Run(ctx); close(done) }()

	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev := <-sink.in:
			if hb := ev.GetHeartbeat(); hb != nil {
				if hb.AgentVersion != "test-version" || hb.Kernel != "5.10.0" {
					t.Fatalf("heartbeat body = %+v", hb)
				}
				if ev.Header.EventType != pb.EventType_AGENT_HEARTBEAT {
					t.Fatalf("heartbeat event_type = %v", ev.Header.EventType)
				}
				cancel()
				<-done
				return
			}
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			cancel()
			t.Fatal("no heartbeat observed within 2s")
		}
	}
}

func TestCollectorsClosedInRegistrationOrder(t *testing.T) {
	sink := &fakeSink{in: make(chan *pb.Event, 64)}
	c1 := newMockCollector("c1", 1)
	c2 := newMockCollector("c2", 1)
	var mu sync.Mutex
	var order []string
	c1.onClose = func() { mu.Lock(); order = append(order, "c1"); mu.Unlock() }
	c2.onClose = func() { mu.Lock(); order = append(order, "c2"); mu.Unlock() }

	rt := newRuntime(t, sink, c1, c2)
	runAndStop(t, rt, allEmitted(c1, c2))

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "c1" || order[1] != "c2" {
		t.Fatalf("close order = %v, want [c1 c2]", order)
	}
}

// 水位原子落盘（R8.4 审计 A-4）：目标文件始终是完整数字（tmp+rename，
// 无截断中间态）；上次崩溃残留的 seq.tmp 被容忍并覆盖，不阻塞保存；
// 覆盖已有水位的第二次保存走替换路径；loadSeq 能读回完整水位。
func TestSaveSeqAtomicReplace(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{SpoolDir: filepath.Join(dir, "spool"), HeartbeatIntervalSec: 3600}
	id := &identity.Identity{AgentID: "agent-1", Hostname: "host-1"}
	rt := New(cfg, id, &fakeSink{in: make(chan *pb.Event, 1)}, "v")

	seqPath := filepath.Join(dir, "seq")
	tmpPath := seqPath + ".tmp"
	// 模拟上次崩溃残留的 tmp：
	if err := os.WriteFile(tmpPath, []byte("torn-garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	rt.saveSeq(42)
	b, err := os.ReadFile(seqPath)
	if err != nil {
		t.Fatalf("read seq after save: %v", err)
	}
	if got := strings.TrimSpace(string(b)); got != "42" {
		t.Fatalf("seq file = %q, want %q", got, "42")
	}
	if _, err := os.Stat(tmpPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat tmp after save = %v, want ErrNotExist (renamed away)", err)
	}

	// 目标文件已存在时再次保存：替换而非追加/截断残留。
	rt.saveSeq(43)
	b, err = os.ReadFile(seqPath)
	if err != nil {
		t.Fatalf("read seq after overwrite: %v", err)
	}
	if got := strings.TrimSpace(string(b)); got != "43" {
		t.Fatalf("seq file after overwrite = %q, want %q", got, "43")
	}

	// 落盘的完整水位可被 loadSeq 读回（+1M 安全垫语义不变）。
	rt2 := New(cfg, id, &fakeSink{in: make(chan *pb.Event, 1)}, "v")
	rt2.loadSeq()
	if got := rt2.seq.Load(); got != 43+1_000_000 {
		t.Fatalf("loadSeq seq = %d, want %d", got, 43+1_000_000)
	}
}
