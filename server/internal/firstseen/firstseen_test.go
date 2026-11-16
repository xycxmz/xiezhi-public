// SPDX-License-Identifier: Apache-2.0

package firstseen

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/xycxmz/xiezhi-public/proto"
	"github.com/xycxmz/xiezhi-public/server/internal/pipeline"
)

// fakeStore 行为仿真 PG：首次见到的键报 new。fail 控制故障注入；block/entered
// 用于把批量循环卡在 Upsert 里，构造队列打满的确定性场景。
type fakeStore struct {
	mu      sync.Mutex
	seen    map[string]bool
	batches [][]Obs
	fail    bool
	entered chan struct{}
	block   chan struct{}
}

func newFakeStore() *fakeStore {
	return &fakeStore{seen: make(map[string]bool)}
}

func (f *fakeStore) Upsert(_ context.Context, obs []Obs) ([]int, error) {
	if f.entered != nil {
		f.entered <- struct{}{}
	}
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batches = append(f.batches, append([]Obs(nil), obs...))
	if f.fail {
		return nil, errors.New("pg down")
	}
	var idx []int
	for i, o := range obs {
		if !f.seen[o.Key] {
			f.seen[o.Key] = true
			idx = append(idx, i)
		}
	}
	return idx, nil
}

func (f *fakeStore) Close() error { return nil }

func (f *fakeStore) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.batches)
}

type fakeSink struct {
	mu     sync.Mutex
	alerts []*pipeline.Alert
}

func (f *fakeSink) EmitAlert(_ context.Context, a *pipeline.Alert) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alerts = append(f.alerts, a)
}

func (f *fakeSink) Close() {}

func (f *fakeSink) snapshot() []*pipeline.Alert {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*pipeline.Alert(nil), f.alerts...)
}

func hdr(t pb.EventType, ts uint64) *pb.EventHeader {
	return &pb.EventHeader{AgentId: "ag1", Hostname: "h1", BootId: "b1", TsMs: ts, EventType: t}
}

func evExecve(ts uint64, exe string) *pb.Event {
	return &pb.Event{Header: hdr(pb.EventType_EXECVE, ts), Body: &pb.Event_Execve{Execve: &pb.ExecveEvent{
		Proc: &pb.ProcessContext{Pid: 7, Exe: exe},
	}}}
}

func evConnect(ts uint64, ip []byte, port uint32) *pb.Event {
	return &pb.Event{Header: hdr(pb.EventType_CONNECT, ts), Body: &pb.Event_Net{Net: &pb.NetEvent{
		Proc: &pb.ProcessContext{Pid: 7}, Ip: ip, Port: port,
	}}}
}

func evDns(ts uint64, server string, port uint32) *pb.Event {
	return &pb.Event{Header: hdr(pb.EventType_DNS_QUERY, ts), Body: &pb.Event_Dns{Dns: &pb.DnsEvent{
		Proc: &pb.ProcessContext{Pid: 7}, ServerIp: server, ServerPort: port,
	}}}
}

func TestExtractKeys(t *testing.T) {
	k := func(kind, host string, parts ...string) string {
		return encodeKey(kind, host, parts...)
	}
	cases := []struct {
		name string
		ev   *pb.Event
		want []string // 期望键集合；nil/空 = 无键
	}{
		{"execve", evExecve(1, "/usr/bin/curl"), []string{k("exe", "h1", "/usr/bin/curl")}},
		{"execve empty exe", evExecve(1, ""), nil},
		{"connect v4", evConnect(1, []byte{1, 2, 3, 4}, 443), []string{k("conn_target", "h1", "1.2.3.4:443")}},
		{"connect loopback v4", evConnect(1, []byte{127, 0, 0, 1}, 443), nil},
		{"connect loopback 127/8", evConnect(1, []byte{127, 5, 6, 7}, 80), nil},
		{"connect loopback v6", evConnect(1, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 443), nil},
		{"connect v6", evConnect(1, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 443), []string{k("conn_target", "h1", "[2001:db8::1]:443")}},
		{"connect port 0", evConnect(1, []byte{1, 2, 3, 4}, 0), nil},
		{"connect no ip", evConnect(1, nil, 443), nil},
		{"dns", evDns(1, "10.0.0.2", 53), []string{k("dns_server", "h1", "10.0.0.2:53")}},
		{"dns empty server", evDns(1, "", 53), nil},
		{"fork has no key", &pb.Event{Header: hdr(pb.EventType_FORK, 1), Body: &pb.Event_Fork{Fork: &pb.ForkEvent{ChildPid: 9}}}, nil},
		{"heartbeat has no key", &pb.Event{Header: hdr(pb.EventType_AGENT_HEARTBEAT, 1), Body: &pb.Event_Heartbeat{Heartbeat: &pb.HeartbeatEvent{}}}, nil},
		{"nil header", &pb.Event{}, nil},
		{"nil event", nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ExtractKeys(c.ev)
			var keys []string
			for _, o := range got {
				keys = append(keys, o.Key)
				if o.Count != 1 {
					t.Errorf("count = %d, want 1", o.Count)
				}
			}
			if len(keys) != len(c.want) {
				t.Fatalf("keys = %v, want %v", keys, c.want)
			}
			for i := range c.want {
				if keys[i] != c.want[i] {
					t.Errorf("key[%d] = %q, want %q", i, keys[i], c.want[i])
				}
			}
		})
	}
}

func TestCacheTTLAndEviction(t *testing.T) {
	var now time.Time
	c := newTTLCache(2, 10*time.Minute, func() time.Time { return now })
	now = time.UnixMilli(1000)
	if !c.AddIfAbsent("a") {
		t.Fatal("first add of a must report absent")
	}
	now = now.Add(time.Minute)
	if c.AddIfAbsent("a") {
		t.Fatal("windowed a must report present")
	}
	// LRU 容量 2：a 被续期前移后，b、c 依次入场 → 最久未用的 a 被挤出，b/c 仍在
	c.AddIfAbsent("b")
	c.AddIfAbsent("c")
	if c.AddIfAbsent("b") {
		t.Fatal("b must still be cached")
	}
	if !c.AddIfAbsent("a") {
		t.Fatal("a (least recently used) should have been evicted by capacity")
	}
	// TTL 过期后重新判 absent
	now = now.Add(11 * time.Minute)
	c2 := newTTLCache(10, time.Minute, func() time.Time { return now })
	c2.AddIfAbsent("x")
	now = now.Add(2 * time.Minute)
	if !c2.AddIfAbsent("x") {
		t.Fatal("expired x must report absent again")
	}
	// Remove 后立刻可重试
	c2.AddIfAbsent("y")
	c2.Remove("y")
	if !c2.AddIfAbsent("y") {
		t.Fatal("removed y must report absent")
	}
}

func TestNewKeyAlertsOnce(t *testing.T) {
	store := newFakeStore()
	sink := &fakeSink{}
	h := New(store, sink, Config{BatchKeys: 10, BatchEvery: time.Hour})
	defer h.Close()
	ctx := context.Background()
	h.Handle(ctx, evExecve(1234, "/tmp/curl"))
	h.Handle(ctx, evExecve(1235, "/tmp/curl")) // LRU 命中，不进管道
	h.Close()
	if got := store.calls(); got != 1 {
		t.Fatalf("upsert calls = %d, want 1 (LRU must absorb the repeat)", got)
	}
	if b := store.batches[0]; len(b) != 1 || b[0].Count != 1 {
		t.Fatalf("batch = %+v, want single curl obs", b)
	}
	// M4 降噪：新键不逐条告警，Close 时按小时窗口发一条 digest
	alerts := sink.snapshot()
	if len(alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(alerts))
	}
	a := alerts[0]
	if a.RuleID != "firstseen/exe/digest" || a.Severity != "info" ||
		!strings.Contains(a.Summary, "host h1 kind exe 首见 1 条（白名单外）") ||
		a.Hostname != "h1" || a.AgentID != "ag1" {
		t.Errorf("alert = %+v", a)
	}
}

func TestKnownKeyColdCacheNoAlert(t *testing.T) {
	store := newFakeStore()
	store.seen[encodeKey("exe", "h1", "/usr/bin/vi")] = true // 冷缓存但 PG 已知
	sink := &fakeSink{}
	h := New(store, sink, Config{})
	h.Handle(context.Background(), evExecve(1, "/usr/bin/vi"))
	h.Close()
	if alerts := sink.snapshot(); len(alerts) != 0 {
		t.Fatalf("known key must not alert, got %+v", alerts)
	}
	if store.calls() != 1 {
		t.Fatalf("cold cache must still reach PG once, calls = %d", store.calls())
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within deadline")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBatchFlushAtSize(t *testing.T) {
	store := newFakeStore()
	h := New(store, &fakeSink{}, Config{BatchKeys: 3, BatchEvery: time.Hour})
	defer h.Close()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		h.Handle(ctx, evConnect(uint64(1000+i), []byte{10, 0, 0, byte(i)}, 80))
	}
	waitFor(t, func() bool { return store.calls() == 1 && len(store.batches[0]) == 3 })
}

func TestQueueFullDrops(t *testing.T) {
	store := newFakeStore()
	store.entered = make(chan struct{}, 8)
	store.block = make(chan struct{})
	h := New(store, &fakeSink{}, Config{BatchKeys: 2, BatchEvery: time.Hour, QueueSize: 4})
	ctx := context.Background()
	h.Handle(ctx, evConnect(1, []byte{10, 0, 0, 1}, 80))
	h.Handle(ctx, evConnect(2, []byte{10, 0, 0, 2}, 80))
	<-store.entered // 批量循环已卡在 Upsert，队列空、容量 4
	for i := 3; i < 13; i++ {
		h.Handle(ctx, evConnect(uint64(i), []byte{10, 0, 0, byte(i)}, 80))
	}
	if got := h.Dropped(); got != 6 {
		t.Fatalf("dropped = %d, want 6 (10 keys - 4 queue slots)", got)
	}
	close(store.block)
	h.Close()
	if got := h.Dropped(); got != 6 {
		t.Fatalf("dropped after close = %d, want 6", got)
	}
}

func TestStoreErrorNoAlert(t *testing.T) {
	store := newFakeStore()
	store.fail = true
	sink := &fakeSink{}
	h := New(store, sink, Config{})
	h.Handle(context.Background(), evExecve(1, "/tmp/x"))
	h.Close()
	if alerts := sink.snapshot(); len(alerts) != 0 {
		t.Fatalf("failed batch must not alert, got %+v", alerts)
	}
	if got := h.FlushFailed(); got != 1 {
		t.Fatalf("flushFailed = %d, want 1 (keys)", got)
	}
}

func TestRegisterParentExe(t *testing.T) {
	store := newFakeStore()
	sink := &fakeSink{}
	h := New(store, sink, Config{})
	h.RegisterParentExe(context.Background(), "h1", "ag1", "/tmp/x", "/bin/bash", 99)
	h.RegisterParentExe(context.Background(), "h1", "ag1", "", "/bin/bash", 99) // 空 exe 无操作
	h.Close()
	alerts := sink.snapshot()
	if len(alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(alerts))
	}
	a := alerts[0]
	if a.RuleID != "firstseen/exe_parent/digest" || a.Severity != "info" ||
		!strings.Contains(a.Summary, "host h1 kind exe_parent 首见 1 条（白名单外）") {
		t.Errorf("alert = %+v", a)
	}
}

func TestKeyEncodingRoundtrip(t *testing.T) {
	key := encodeKey(KindExeParent, "host-a", "/usr/bin/find", "/bin/bash")
	parts := strings.Split(key, keySep)
	if len(parts) != 4 || parts[0] != KindExeParent || parts[1] != "host-a" {
		t.Fatalf("key encoding changed shape: %q", key)
	}
}
