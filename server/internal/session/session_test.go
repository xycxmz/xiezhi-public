// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

type savedTree struct {
	row   TreeRow
	nodes []NodeRow
}

type fakeStore struct {
	mu    sync.Mutex
	trees []savedTree
	fail  bool
}

func (f *fakeStore) SaveTree(_ context.Context, t *TreeRow, nodes []NodeRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("pg down")
	}
	f.trees = append(f.trees, savedTree{row: *t, nodes: append([]NodeRow(nil), nodes...)})
	return nil
}

func (f *fakeStore) QueryLatestTreeByPID(_ context.Context, host string, pid int32) (*TreeRow, []NodeRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.trees) - 1; i >= 0; i-- {
		s := f.trees[i]
		if s.row.Host != host {
			continue
		}
		for _, n := range s.nodes {
			if n.Pid == pid {
				row, nodes := s.row, append([]NodeRow(nil), s.nodes...)
				return &row, nodes, nil
			}
		}
	}
	return nil, nil, nil
}

func (f *fakeStore) Close() error { return nil }

func (f *fakeStore) saved() []savedTree {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]savedTree(nil), f.trees...)
}

// slowStore 模拟 PG 慢写：SaveTree 固定睡 delay 再落库。
type slowStore struct {
	fakeStore
	delay time.Duration
}

func (s *slowStore) SaveTree(ctx context.Context, tr *TreeRow, nodes []NodeRow) error {
	time.Sleep(s.delay)
	return s.fakeStore.SaveTree(ctx, tr, nodes)
}

// gatedStore 卡住 SaveTree 直到 release 关闭：把 worker 按停在第一次 PG 写
// 上，归档队列得以确定性灌满。
type gatedStore struct {
	fakeStore
	entered chan struct{}
	release chan struct{}
}

func (g *gatedStore) SaveTree(ctx context.Context, tr *TreeRow, nodes []NodeRow) error {
	select {
	case g.entered <- struct{}{}:
	default:
	}
	<-g.release
	return g.fakeStore.SaveTree(ctx, tr, nodes)
}

// panicStore 模拟 Store 实现自带 bug（R8.4 复审 F-001）：第一次 SaveTree
// panic，其后恢复正常——验证归档 worker 的 per-tree recover。
type panicStore struct {
	fakeStore
	panicked bool // 仅 worker goroutine 读写，无需加锁
}

func (p *panicStore) SaveTree(ctx context.Context, tr *TreeRow, nodes []NodeRow) error {
	if !p.panicked {
		p.panicked = true
		panic("store impl bug")
	}
	return p.fakeStore.SaveTree(ctx, tr, nodes)
}

// waitFor 轮询等异步归档 worker 的可观测结果（C-4 归档改异步后，测试不再
// read-your-writes）：cond 为真即返，超时失败。
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

type fakeRegistrar struct {
	mu    sync.Mutex
	calls [][4]string // host, exe, parentExe, agentID
}

func (f *fakeRegistrar) RegisterParentExe(_ context.Context, host, agentID, exe, parentExe string, _ int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, [4]string{host, exe, parentExe, agentID})
}

func (f *fakeRegistrar) snapshot() [][4]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][4]string(nil), f.calls...)
}

func hdr(t pb.EventType, ts uint64) *pb.EventHeader {
	return &pb.EventHeader{AgentId: "ag1", Hostname: "h1", BootId: "b1", TsMs: ts, EventType: t}
}

func evFork(ts uint64, parentPid uint32, parentExe string, childPid uint32, childTicks uint64) *pb.Event {
	return &pb.Event{Header: hdr(pb.EventType_FORK, ts), Body: &pb.Event_Fork{Fork: &pb.ForkEvent{
		Parent:   &pb.ProcessContext{Pid: parentPid, Ppid: 1, Exe: parentExe},
		ChildPid: childPid, ChildStartTicks: childTicks,
	}}}
}

func evExecve(ts uint64, pid, ppid uint32, exe string, argv ...string) *pb.Event {
	return evExecveTicks(ts, pid, ppid, exe, 0, argv...)
}

func evExecveTicks(ts uint64, pid, ppid uint32, exe string, ticks uint64, argv ...string) *pb.Event {
	return &pb.Event{Header: hdr(pb.EventType_EXECVE, ts), Body: &pb.Event_Execve{Execve: &pb.ExecveEvent{
		Proc: &pb.ProcessContext{Pid: pid, Ppid: ppid, Exe: exe, Argv: argv, StartTicks: ticks},
	}}}
}

func evExit(ts uint64, pid uint32, ticks uint64) *pb.Event {
	return &pb.Event{Header: hdr(pb.EventType_EXIT, ts), Body: &pb.Event_Exit{Exit: &pb.ExitEvent{Pid: pid, StartTicks: ticks}}}
}

func evNet(ts uint64, pid uint32) *pb.Event {
	return &pb.Event{Header: hdr(pb.EventType_CONNECT, ts), Body: &pb.Event_Net{Net: &pb.NetEvent{
		Proc: &pb.ProcessContext{Pid: pid}, Ip: []byte{1, 2, 3, 4}, Port: 443,
	}}}
}

func cfg() Config {
	return Config{IdleArchive: 10 * time.Minute, SweepEvery: time.Hour, MaxNodesPerHost: 1000}
}

func TestForkExecveBuildAndSubtree(t *testing.T) {
	h := New(&fakeStore{}, nil, cfg())
	defer h.Close()
	ctx := context.Background()
	h.Handle(ctx, evFork(1000, 10, "/bin/bash", 11, 5000))
	h.Handle(ctx, evExecve(1001, 11, 10, "/usr/bin/curl", "curl", "http://x"))

	want := "pid=10 exe=/bin/bash argv=\"\"\n  pid=11 exe=/usr/bin/curl argv=\"curl http://x\"\n"
	for _, depth := range []int{-1, 5} {
		got, err := h.SubtreeJSON("h1", 10, depth)
		if err != nil {
			t.Fatalf("depth %d: %v", depth, err)
		}
		if got != want {
			t.Fatalf("depth %d subtree:\n%s\nwant:\n%s", depth, got, want)
		}
	}
	// 锚定中间节点只渲染其子树
	got, err := h.SubtreeJSON("h1", 11, -1)
	if err != nil {
		t.Fatal(err)
	}
	if want := "pid=11 exe=/usr/bin/curl argv=\"curl http://x\"\n"; got != want {
		t.Fatalf("mid-anchor subtree:\n%q\nwant:\n%q", got, want)
	}
}

func TestSubtreeDepth(t *testing.T) {
	h := New(&fakeStore{}, nil, cfg())
	defer h.Close()
	ctx := context.Background()
	h.Handle(ctx, evFork(1, 10, "/bin/bash", 11, 1))
	h.Handle(ctx, evExecve(2, 11, 10, "/usr/bin/sh"))
	h.Handle(ctx, evFork(3, 11, "/usr/bin/sh", 12, 2))
	h.Handle(ctx, evExecve(4, 12, 11, "/usr/bin/find", "find", "/"))
	cases := []struct {
		depth int
		want  string
	}{
		{0, "pid=10 exe=/bin/bash argv=\"\"\n"},
		{1, "pid=10 exe=/bin/bash argv=\"\"\n  pid=11 exe=/usr/bin/sh argv=\"\"\n"},
		{-1, "pid=10 exe=/bin/bash argv=\"\"\n  pid=11 exe=/usr/bin/sh argv=\"\"\n    pid=12 exe=/usr/bin/find argv=\"find /\"\n"},
	}
	for _, c := range cases {
		got, err := h.SubtreeJSON("h1", 10, c.depth)
		if err != nil {
			t.Fatalf("depth %d: %v", c.depth, err)
		}
		if got != c.want {
			t.Fatalf("depth %d:\n%q\nwant:\n%q", c.depth, got, c.want)
		}
	}
}

func TestExecveOrphanThenForkAttach(t *testing.T) {
	h := New(&fakeStore{}, nil, cfg())
	defer h.Close()
	ctx := context.Background()
	// 早于 agent 启动的存量进程：无 FORK 前史的 EXECVE 建孤立根
	h.Handle(ctx, evExecve(1, 700, 1, "/bin/sh"))
	h.Handle(ctx, evFork(2, 700, "/bin/sh", 701, 9))
	got, err := h.SubtreeJSON("h1", 700, -1)
	if err != nil {
		t.Fatal(err)
	}
	want := "pid=700 exe=/bin/sh argv=\"\"\n  pid=701 exe= argv=\"\"\n"
	if got != want {
		t.Fatalf("orphan tree:\n%q\nwant:\n%q", got, want)
	}
}

func TestExitWholeTreeArchivesAndCallback(t *testing.T) {
	store := &fakeStore{}
	reg := &fakeRegistrar{}
	h := New(store, reg, cfg())
	defer h.Close()
	ctx := context.Background()
	h.Handle(ctx, evFork(1000, 10, "/bin/bash", 11, 5000))
	h.Handle(ctx, evExecve(1001, 11, 10, "/usr/bin/curl", "curl", "evil.sh"))
	// 子退出：进墓园、树仍活、pid 槽位释放
	h.Handle(ctx, evExit(1002, 11, 5000))
	if _, err := h.SubtreeJSON("h1", 11, -1); err == nil {
		t.Fatal("exited pid must be gone from the live index before tree archive")
	}
	if len(store.saved()) != 0 {
		t.Fatal("tree with a live root must not archive on child exit")
	}
	// 根退出：整树退空，归档只入队（异步）；回调是 archive 的最后一步，
	// 等到它即保证落库与计数都已就绪
	h.Handle(ctx, evExit(1003, 10, 0))
	waitFor(t, "parentExe callback", func() bool { return len(reg.snapshot()) == 1 })

	saved := store.saved()
	if len(saved) != 1 {
		t.Fatalf("saved trees = %d, want 1", len(saved))
	}
	s := saved[0]
	if s.row.RootPid != 10 || s.row.Host != "h1" || s.row.AgentID != "ag1" || s.row.NodeCount != 2 {
		t.Errorf("tree row = %+v", s.row)
	}
	if len(s.nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(s.nodes))
	}
	for _, n := range s.nodes {
		if !n.Exited {
			t.Errorf("node %d must be archived as exited", n.Pid)
		}
	}
	if got := h.NodesArchived(); got != 2 {
		t.Errorf("nodesArchived = %d, want 2", got)
	}
	// 回调：树内 distinct (exe, parent_exe) 恰一组（waitFor 已保证送达）
	calls := reg.snapshot()
	if len(calls) != 1 || calls[0] != [4]string{"h1", "/usr/bin/curl", "/bin/bash", "ag1"} {
		t.Fatalf("parentExe calls = %+v", calls)
	}
	// 内存已清：锚定查询回落 PG 重建，形状与内存渲染一致
	got, err := h.SubtreeJSON("h1", 11, -1)
	if err != nil {
		t.Fatal(err)
	}
	want := "pid=11 exe=/usr/bin/curl argv=\"curl evil.sh\" [exited]\n"
	if got != want {
		t.Fatalf("PG-fallback subtree:\n%q\nwant:\n%q", got, want)
	}
}

func TestIdleArchive(t *testing.T) {
	store := &fakeStore{}
	h := New(store, nil, cfg())
	defer h.Close()
	h.Handle(context.Background(), evFork(1000, 10, "/bin/bash", 11, 5000))
	h.sweepOnce(time.Now().Add(11 * time.Minute))
	waitFor(t, "idle archive", func() bool { return len(store.saved()) == 1 })
	if _, err := h.SubtreeJSON("h1", 10, -1); err != nil {
		t.Fatalf("post-archive anchor must fall back to store: %v", err)
	}
}

func TestTouchKeepsTreeAlive(t *testing.T) {
	store := &fakeStore{}
	h := New(store, nil, cfg())
	defer h.Close()
	ctx := context.Background()
	h.Handle(ctx, evFork(1000, 10, "/bin/bash", 11, 5000))
	h.Handle(ctx, evExecve(1001, 11, 10, "/usr/bin/sshd"))
	// 网络事件刷活动时钟：+9min 未达 10min 阈值不归档
	h.Handle(ctx, evNet(1002, 11))
	h.sweepOnce(time.Now().Add(9 * time.Minute))
	if len(store.saved()) != 0 {
		t.Fatal("touched tree must survive a sub-threshold sweep")
	}
	h.sweepOnce(time.Now().Add(11 * time.Minute))
	waitFor(t, "idle archive", func() bool { return len(store.saved()) == 1 })
}

func TestEvictionDropsOldestRoot(t *testing.T) {
	store := &fakeStore{}
	c := cfg()
	c.MaxNodesPerHost = 2
	h := New(store, nil, c)
	defer h.Close()
	ctx := context.Background()
	h.Handle(ctx, evFork(1000, 10, "/bin/bash", 11, 1))    // 树 A，2 节点
	h.Handle(ctx, evExecve(1001, 20, 1, "/usr/sbin/cron")) // 树 B，1 节点 → 超上界
	h.sweepOnce(time.Now())
	if got := h.EvictedRoots(); got != 1 {
		t.Fatalf("evictedRoots = %d, want 1", got)
	}
	waitFor(t, "evicted tree archive", func() bool { return len(store.saved()) == 1 })
	saved := store.saved()
	if len(saved) != 1 || saved[0].row.RootPid != 10 {
		t.Fatalf("oldest tree must be evicted-archived first, saved = %+v", saved)
	}
	// 幸存树仍在内存
	if _, err := h.SubtreeJSON("h1", 20, -1); err != nil {
		t.Fatalf("newer tree must stay in memory: %v", err)
	}
}

func TestPidReuseAfterExit(t *testing.T) {
	h := New(&fakeStore{}, nil, cfg())
	defer h.Close()
	ctx := context.Background()
	h.Handle(ctx, evFork(1, 10, "/bin/bash", 11, 100))
	h.Handle(ctx, evExecve(2, 11, 10, "/bin/sleep", "sleep", "1"))
	h.Handle(ctx, evExit(3, 11, 100))
	// 同 pid 新化身（ticks 不同）：新节点，不覆盖墓园
	h.Handle(ctx, evFork(4, 10, "/bin/bash", 11, 200))
	h.Handle(ctx, evExecve(5, 11, 10, "/usr/bin/wget", "wget", "x"))
	got, err := h.SubtreeJSON("h1", 10, -1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "/bin/sleep") || !strings.Contains(got, "[exited]") {
		t.Fatalf("graveyard incarnation lost:\n%s", got)
	}
	if !strings.Contains(got, "/usr/bin/wget") {
		t.Fatalf("new incarnation missing:\n%s", got)
	}
	// 指向旧化身的迟到 EXIT（ticks=100 ≠ 200）：不摘新化身，树保持活
	h.Handle(ctx, evExit(6, 11, 100))
	if got := h.UnknownExits(); got != 1 {
		t.Errorf("unknownExits = %d, want 1", got)
	}
	if _, err := h.SubtreeJSON("h1", 11, -1); err != nil {
		t.Fatalf("new incarnation must still be live: %v", err)
	}
}

func TestExecveTicksMismatchNewIncarnation(t *testing.T) {
	h := New(&fakeStore{}, nil, cfg())
	defer h.Close()
	ctx := context.Background()
	h.Handle(ctx, evExecveTicks(1, 50, 1, "/old/image", 100))
	// 带 ticks 的 execve 与活节点 ticks 不符 = 复用，旧化身进墓园、新建根
	h.Handle(ctx, evExecveTicks(2, 50, 1, "/new/image", 9, "x"))
	if got := h.PidCollisions(); got != 1 {
		t.Fatalf("pidCollisions = %d, want 1", got)
	}
	got, err := h.SubtreeJSON("h1", 50, -1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "/new/image") {
		t.Fatalf("new incarnation not queryable:\n%s", got)
	}
}

func TestArgvTruncatedOnRuneBoundary(t *testing.T) {
	store := &fakeStore{}
	h := New(store, nil, cfg())
	defer h.Close()
	ctx := context.Background()
	long := strings.Repeat("好", 200) // 600B，截断须落在 rune 边界且 ≤256B
	h.Handle(ctx, evFork(1, 10, "/bin/bash", 11, 1))
	h.Handle(ctx, evExecve(2, 11, 10, "/usr/bin/x", long))
	h.Handle(ctx, evExit(3, 11, 1))
	h.Handle(ctx, evExit(4, 10, 0))
	waitFor(t, "tree archive", func() bool { return len(store.saved()) == 1 })
	saved := store.saved()
	if len(saved) != 1 {
		t.Fatalf("saved = %d, want 1", len(saved))
	}
	for _, n := range saved[0].nodes {
		if len(n.Argv) > maxArgvBytes {
			t.Errorf("pid %d argv %dB exceeds limit", n.Pid, len(n.Argv))
		}
		if !utf8.ValidString(n.Argv) {
			t.Errorf("pid %d argv not valid UTF-8: %q", n.Pid, n.Argv)
		}
		if n.Exe != "/usr/bin/x" && n.Exe != "/bin/bash" {
			t.Errorf("unexpected exe %q", n.Exe)
		}
	}
}

func TestSubtreeJSONErrorsWithoutStore(t *testing.T) {
	h := New(nil, nil, cfg())
	defer h.Close()
	if _, err := h.SubtreeJSON("h1", 4242, -1); err == nil {
		t.Fatal("unknown pid with no store must error")
	}
	if _, err := h.SubtreeJSON("h1", 0, -1); err == nil {
		t.Fatal("invalid pid must error")
	}
}

func TestCloseArchivesRemainder(t *testing.T) {
	store := &fakeStore{}
	h := New(store, nil, cfg())
	h.Handle(context.Background(), evFork(1, 10, "/bin/bash", 11, 1))
	h.Close()
	if len(store.saved()) != 1 {
		t.Fatalf("Close must flush live trees, saved = %d", len(store.saved()))
	}
}

// TestHandleNotBlockedBySlowPG（C-4）：PG 慢写时 Handle 必须快速返回——
// 归档只入队、由 worker 异步执行，绝不阻塞 ingest 主路径。
func TestHandleNotBlockedBySlowPG(t *testing.T) {
	store := &slowStore{delay: 400 * time.Millisecond}
	h := New(store, nil, cfg())
	defer h.Close()
	ctx := context.Background()
	h.Handle(ctx, evFork(1000, 10, "/bin/bash", 11, 1))
	start := time.Now()
	h.Handle(ctx, evExit(1001, 11, 1)) // 整树退空：触发归档（慢 PG 写在 worker 里）
	h.Handle(ctx, evExit(1002, 10, 0))
	if el := time.Since(start); el > 150*time.Millisecond {
		t.Fatalf("Handle blocked %v on slow PG; async archive must not block ingest", el)
	}
	waitFor(t, "slow archive to finish", func() bool { return h.TreesArchived() == 1 })
}

// TestArchiveQueueFullDrops（C-4）：worker 卡在慢 PG 写上、队列灌满后，入队
// 必须非阻塞——丢弃并计数 archiveDropped；Close 停队列后 worker 把剩余树
// 全部写完才退（排干语义）。
func TestArchiveQueueFullDrops(t *testing.T) {
	g := &gatedStore{entered: make(chan struct{}, 1), release: make(chan struct{})}
	h := New(g, nil, cfg())
	h.enqueueArchive(&tree{root: &node{pid: 1}}) // 卡住 worker
	<-g.entered
	for i := 0; i < archiveQueueCap; i++ { // 灌满队列
		h.enqueueArchive(&tree{root: &node{pid: uint32(i + 2)}})
	}
	h.enqueueArchive(&tree{root: &node{pid: 9999}}) // 满：丢弃计数
	if got := h.ArchiveDropped(); got != 1 {
		t.Fatalf("archiveDropped = %d, want 1", got)
	}
	close(g.release)
	h.Close()
	if got := h.TreesArchived(); got != archiveQueueCap+1 {
		t.Fatalf("Close must drain the queue, treesArchived = %d, want %d", got, archiveQueueCap+1)
	}
}

// TestArchiveWorkerRecoversStorePanic（R8.4 复审 F-001）：归档 worker 是实现
// 自有的裸 goroutine，pipeline M3 契约（handler panic 自行 recover 并计数）
// 由它自己承担——Store 写路径 panic 必须只丢当前树、计入 panics，worker
// 继续消费后续树；否则一树 panic 直接击穿整个 server 进程（本测试二进制
// 本身跑完即「进程不退」的证明：未恢复的 panic 会连 test 进程一起崩）。
func TestArchiveWorkerRecoversStorePanic(t *testing.T) {
	store := &panicStore{}
	h := New(store, nil, cfg())
	defer h.Close()
	ctx := context.Background()
	// 两棵独立树先后整树退出：第一棵触发 SaveTree panic，第二棵必须照常落库
	h.Handle(ctx, evExecve(1, 10, 1, "/bin/bash"))
	h.Handle(ctx, evExecve(2, 20, 1, "/usr/bin/curl"))
	h.Handle(ctx, evExit(3, 10, 0))
	h.Handle(ctx, evExit(4, 20, 0))
	waitFor(t, "post-panic tree archive", func() bool { return h.TreesArchived() == 1 })
	if got := h.Panics(); got < 1 {
		t.Fatalf("panics = %d, want >= 1", got)
	}
	saved := store.saved()
	if len(saved) != 1 || saved[0].row.RootPid != 20 {
		t.Fatalf("tree after the panicking one must still archive, saved = %+v", saved)
	}
}
