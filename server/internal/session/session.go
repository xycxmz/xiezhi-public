// SPDX-License-Identifier: Apache-2.0

// Package session 实现 session 进程树聚合（数百台 ECS 日增
// 十亿边级，全量上传建图被规模数据否决——按 FORK/EXECVE/EXIT 在服务端建
// per-host 树，空闲或整树退出即归档，兼作 LLM 研判的证据打包器）。
//
// 树的增删改仍在 Handle 锁内同步完成（µs 级 O(树深) 的内存变更，
// SubtreeJSON 对内存树的 read-your-writes 依然成立）；归档是唯一异步段
// （R8.4 审计 C-4）：整树退出/boot 退役/上界驱逐/空闲 sweep 摘下的树一律
// 投入有界归档队列，单 worker 在锁外做 PG 写与 firstseen 回调——PG 慢或
// 故障时每棵退出的树不再卡该 agent 流最长 10s，队列满丢弃计数
// （archiveDropped）。代价：树自内存摘除到落 PG 之间有一段锚定查询空窗
// （内存未命中、PG 亦未到），ingest 不阻塞优先，此即取舍。
package session

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

// Config 可调项。默认值即 brief 给定：空闲归档 10min、单主机节点上界 200k。
type Config struct {
	IdleArchive     time.Duration
	SweepEvery      time.Duration
	MaxNodesPerHost int
}

func (c Config) withDefaults() Config {
	if c.IdleArchive <= 0 {
		c.IdleArchive = 10 * time.Minute
	}
	if c.SweepEvery <= 0 {
		c.SweepEvery = time.Minute
	}
	if c.MaxNodesPerHost <= 0 {
		c.MaxNodesPerHost = 200_000
	}
	return c
}

// ParentExeRegistrar 是 firstseen 回调接口（main 接线注入）：树归档时，
// session 把树内每个 distinct (exe, parent_exe) 组合喂给 firstseen 的第四类
// 键。*firstseen.Handler 直接满足本接口（RegisterParentExe 同签名）。
type ParentExeRegistrar interface {
	RegisterParentExe(ctx context.Context, host, agentID, exe, parentExe string, tsMs int64)
}

type stats struct {
	unknownExit    atomic.Uint64
	pidCollision   atomic.Uint64
	nodeCapDrops   atomic.Uint64
	evictedRoots   atomic.Uint64 // sweep 驱逐 + 写路径上界驱逐（makeRoom）共用的计数
	archiveDropped atomic.Uint64 // 归档队列满被丢弃的树数（PG 故障积压的兜底计数）
}

// archiveQueueCap 是归档队列容量：正常负载下退出的树远不及此速率；
// PG 故障积压打满时按丢弃纪律计数（archiveDropped），绝不回压 ingest。
const archiveQueueCap = 1024

type Handler struct {
	cfg    Config
	store  Store              // 可为 nil（纯内存模式，归档仅回调 firstseen）
	parent ParentExeRegistrar // 可为 nil（未接线时跳过回填）

	mu    sync.Mutex
	hosts map[string]*hostTree
	stats *stats

	treesArchived atomic.Uint64
	nodesArchived atomic.Uint64
	archiveFailed atomic.Uint64
	panics        atomic.Uint64

	stop        chan struct{}
	done        chan struct{}
	archiveCh   chan *tree    // 归档队列（有界，满即丢弃计数）
	archiveDone chan struct{} // 归档 worker 排干退出信号
	closeOnce   sync.Once
}

func New(store Store, parent ParentExeRegistrar, cfg Config) *Handler {
	cfg = cfg.withDefaults()
	h := &Handler{
		cfg:         cfg,
		store:       store,
		parent:      parent,
		hosts:       make(map[string]*hostTree),
		stats:       &stats{},
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
		archiveCh:   make(chan *tree, archiveQueueCap),
		archiveDone: make(chan struct{}),
	}
	go h.run()
	go h.archiveWorker()
	return h
}

func (h *Handler) Name() string { return "session" }

func (h *Handler) TreesArchived() uint64 { return h.treesArchived.Load() }
func (h *Handler) NodesArchived() uint64 { return h.nodesArchived.Load() }
func (h *Handler) EvictedRoots() uint64  { return h.stats.evictedRoots.Load() }
func (h *Handler) ArchiveFailed() uint64 { return h.archiveFailed.Load() }
func (h *Handler) ArchiveDropped() uint64 {
	return h.stats.archiveDropped.Load()
}
func (h *Handler) UnknownExits() uint64  { return h.stats.unknownExit.Load() }
func (h *Handler) PidCollisions() uint64 { return h.stats.pidCollision.Load() }
func (h *Handler) NodeCapDrops() uint64  { return h.stats.nodeCapDrops.Load() }
func (h *Handler) Panics() uint64        { return h.panics.Load() }

// Stats 是计数面的只读快照（consoleapi 的 session 段取数入口），字段与
// 各 getter 同源。
type Stats struct {
	TreesArchived  uint64
	NodesArchived  uint64
	ArchiveFailed  uint64 // PG 写失败丢弃的树数
	ArchiveDropped uint64 // 归档队列满丢弃的树数
	EvictedRoots   uint64
	UnknownExits   uint64
	PidCollisions  uint64
	NodeCapDrops   uint64
	Panics         uint64
}

func (h *Handler) Stats() Stats {
	return Stats{
		TreesArchived:  h.treesArchived.Load(),
		NodesArchived:  h.nodesArchived.Load(),
		ArchiveFailed:  h.archiveFailed.Load(),
		ArchiveDropped: h.stats.archiveDropped.Load(),
		EvictedRoots:   h.stats.evictedRoots.Load(),
		UnknownExits:   h.stats.unknownExit.Load(),
		PidCollisions:  h.stats.pidCollision.Load(),
		NodeCapDrops:   h.stats.nodeCapDrops.Load(),
		Panics:         h.panics.Load(),
	}
}

// Handle 非阻塞：树变更在锁内 O(树深) 完成，归档（PG 写 + firstseen 回调）
// 只入队、由 worker 异步执行。recover 是 pipeline M3 契约。
func (h *Handler) Handle(_ context.Context, ev *pb.Event) {
	defer h.recoverPanic("Handle")
	if ev == nil || ev.Header == nil {
		return
	}
	hdr := ev.Header
	now := time.Now()
	ts := int64(hdr.TsMs)
	if ts <= 0 {
		ts = now.UnixMilli()
	}
	h.mu.Lock()
	ht, retired := h.hostFor(hdr)
	var done *tree
	switch hdr.EventType {
	case pb.EventType_FORK:
		if f := ev.GetFork(); f != nil {
			done = ht.fork(f.GetParent(), f.GetChildPid(), f.GetChildStartTicks(), ts, now)
		}
	case pb.EventType_EXECVE:
		if e := ev.GetExecve(); e != nil {
			done = ht.execve(e.GetProc(), ts, now)
		}
	case pb.EventType_EXIT:
		if x := ev.GetExit(); x != nil {
			done = ht.exit(x.GetPid(), x.GetStartTicks(), ts, now)
		}
	default:
		// 其余带 ProcessContext 的事件只刷活动时钟：活跃树不归档，
		// 长连接/长任务进程的证据窗口因此保持活着。
		if p := procOf(ev); p != nil {
			ht.touch(p.GetPid(), ts, now)
		}
	}
	h.mu.Unlock()
	if done != nil {
		h.enqueueArchive(done)
	}
	for _, t := range retired {
		h.enqueueArchive(t)
	}
	// 写路径上界驱逐（makeRoom）的树同样只入队
	h.mu.Lock()
	evicted := ht.pendingEvict
	ht.pendingEvict = nil
	h.mu.Unlock()
	for _, t := range evicted {
		h.enqueueArchive(t)
	}
}

// hostFor 取主机树。boot_id 变化（主机重启、agent 换 boot 重连）时整体退役
// 旧树（返回给调用方在锁外归档）并新建空树：重启后 pid 空间已重置，旧树的
// 槽位不能再错配新化身的事件、exe_parent 基线不能跨 boot 混算。任一侧
// boot_id 为空（旧版 agent）时维持原有按 hostname 合并的行为。
func (h *Handler) hostFor(hdr *pb.EventHeader) (*hostTree, []*tree) {
	ht, ok := h.hosts[hdr.Hostname]
	if !ok {
		ht = newHostTree(hdr.Hostname, hdr.AgentId, hdr.BootId, h.cfg.MaxNodesPerHost, h.stats)
		h.hosts[hdr.Hostname] = ht
		return ht, nil
	}
	if hdr.BootId != "" && ht.bootID != "" && hdr.BootId != ht.bootID {
		retired := ht.trees
		ht = newHostTree(hdr.Hostname, hdr.AgentId, hdr.BootId, h.cfg.MaxNodesPerHost, h.stats)
		h.hosts[hdr.Hostname] = ht
		return ht, retired
	}
	return ht, nil
}

// procOf 抽取事件的主体进程上下文（无进程主体的事件返回 nil）。
func procOf(ev *pb.Event) *pb.ProcessContext {
	switch ev.Header.EventType {
	case pb.EventType_EXECVE:
		return ev.GetExecve().GetProc()
	case pb.EventType_CONNECT, pb.EventType_BIND, pb.EventType_ACCEPT:
		return ev.GetNet().GetProc()
	case pb.EventType_DNS_QUERY:
		return ev.GetDns().GetProc()
	case pb.EventType_FILE_OPEN, pb.EventType_FILE_CREATE, pb.EventType_FILE_RENAME, pb.EventType_FILE_UNLINK, pb.EventType_FILE_LINK:
		return ev.GetFile().GetProc()
	case pb.EventType_MEMFD_CREATE, pb.EventType_MPROT_EXEC:
		return ev.GetMemExec().GetProc()
	case pb.EventType_MODULE_LOAD, pb.EventType_USERMODE_HELPER, pb.EventType_BPF_LOAD:
		return ev.GetKernelModule().GetProc()
	case pb.EventType_PTRACE:
		return ev.GetPtrace().GetTracer()
	case pb.EventType_SETSID, pb.EventType_PRCTL_NAME:
		return ev.GetMisc().GetProc()
	default:
		return nil
	}
}

func (h *Handler) run() {
	defer close(h.done)
	ticker := time.NewTicker(h.cfg.SweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.sweepOnce(time.Now())
		case <-h.stop:
			return
		}
	}
}

// sweepOnce 一轮扫描（与 deadman.scanOnce 同款可测结构）：树根空闲超阈值即
// 归档；单主机节点数超上界时从最旧树起整树丢弃（先尽力归档，内存上界是硬
// 要求，归档失败也丢并计数）。
func (h *Handler) sweepOnce(now time.Time) {
	h.mu.Lock()
	var archive []*tree
	for _, ht := range h.hosts {
		remaining := ht.trees[:0]
		for _, t := range ht.trees {
			if now.Sub(t.lastActive) >= h.cfg.IdleArchive {
				archive = append(archive, t)
				ht.detachTreeIndexes(t)
				continue
			}
			remaining = append(remaining, t)
		}
		ht.trees = remaining
		for ht.nodeCount > h.cfg.MaxNodesPerHost && len(ht.trees) > 0 {
			oldest := 0
			for i, t := range ht.trees {
				if t.lastActive.Before(ht.trees[oldest].lastActive) {
					oldest = i
				}
			}
			t := ht.trees[oldest]
			ht.trees = append(ht.trees[:oldest], ht.trees[oldest+1:]...)
			ht.detachTreeIndexes(t)
			archive = append(archive, t)
			h.stats.evictedRoots.Add(1)
		}
	}
	h.mu.Unlock()
	for _, t := range archive {
		h.enqueueArchive(t)
	}
}

// Close 停扫描，把内存中剩余树全部入队并停归档队列，等 worker 把队列排干
// （退出前证据 flush：剩余树写完才退），最后关自有 store。
// 契约：Close 后不得再调用 Handle/sweepOnce（R8.4 复审 F-002）——
// close(archiveCh) 与并发 Handle 的 enqueueArchive 发送之间存在
// send-on-closed-channel 窗口；生产接线（main.go 先 GracefulStop 等全部
// in-flight handler 结束，再 pipe.Close 触发 Close）已保证此顺序。
func (h *Handler) Close() {
	h.closeOnce.Do(func() {
		close(h.stop)
		<-h.done
		h.mu.Lock()
		var all []*tree
		for k, ht := range h.hosts {
			all = append(all, ht.trees...)
			ht.trees = nil
			delete(h.hosts, k)
		}
		h.mu.Unlock()
		for _, t := range all {
			h.enqueueArchive(t)
		}
		close(h.archiveCh)
		<-h.archiveDone
		if h.store != nil {
			if err := h.store.Close(); err != nil {
				slog.Warn("session store close", "err", err)
			}
		}
	})
}

// SubtreeJSON 是 M4 LLM 研判的告警锚定查询：给 (host, pid)，序列化该节点
// 子树为缩进树文本（每级 2 空格，exe/argv 已截断）。depth 语义：<0 整棵
// 子树，0 仅本节点，n 向下 n 层。内存优先；未命中回落查含该 pid 的最近一次
// PG 归档；两处皆无返回错误。M3 不接 gRPC，导出 Go 函数供上层调用。
// 命名沿用 brief 的 SubtreeJSON，但产出是缩进文本而非 JSON（brief 明文约
// 定「序列化成缩进树文本」）。
func (h *Handler) SubtreeJSON(host string, pid int32, depth int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("session: invalid pid %d", pid)
	}
	// 渲染必须持锁（R8.4 审计 C-1）：节点 exe/argv/children 由 Handle 并发
	// 写，锁外读 slice header 可撕裂——llm worker 无 recover，撕裂 panic
	// 击穿整个进程。锁内渲染换一致快照（深度限 8、宽度小，锁持有可忽略）；
	// 归档回退查询在锁外。
	h.mu.Lock()
	var n *node
	if ht, ok := h.hosts[host]; ok {
		n = ht.byPid[uint32(pid)]
	}
	var out string
	if n != nil {
		out = renderSubtree(n, depth)
	}
	h.mu.Unlock()
	if n != nil {
		return out, nil
	}
	if h.store == nil {
		return "", fmt.Errorf("session: pid %d on host %q not in memory and no store configured", pid, host)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, rows, err := h.store.QueryLatestTreeByPID(ctx, host, pid)
	if err != nil {
		return "", fmt.Errorf("session: query archived tree host %q pid %d: %w", host, pid, err)
	}
	if len(rows) == 0 {
		return "", fmt.Errorf("session: no archived tree has pid %d on host %q", pid, host)
	}
	anchor := rebuildNodes(rows, uint32(pid))
	if anchor == nil {
		return "", fmt.Errorf("session: pid %d lost in rebuild on host %q", pid, host)
	}
	return renderSubtree(anchor, depth), nil
}

func (h *Handler) recoverPanic(where string) {
	if r := recover(); r != nil {
		h.panics.Add(1)
		slog.Error("session panic recovered", "where", where, "panic", r)
	}
}

// enqueueArchive 把待归档树非阻塞投入队列（整树退出/boot 退役/上界驱逐/
// 空闲 sweep/Close flush 共用入口）：队列满即丢弃计数（archiveDropped）
// ——归档是 best-effort 证据留存，绝不能反过来阻塞 ingest 主路径。
func (h *Handler) enqueueArchive(t *tree) {
	select {
	case h.archiveCh <- t:
	default:
		h.stats.archiveDropped.Add(1)
		slog.Warn("session archive queue full, tree dropped", "host", t.host, "root_pid", t.root.pid)
	}
}

// archiveWorker 单 worker 顺序消费归档队列（整树退出顺序即证据落库顺序），
// 队列关闭后排干剩余树才退出。
func (h *Handler) archiveWorker() {
	defer close(h.archiveDone)
	for t := range h.archiveCh {
		h.archive(t)
	}
}

// archive 是 worker 侧的归档实现：先在锁外把树内容定格成行，PG 落库
// （失败丢弃计数——内存上界优先，纪律同 store.Batcher），再对 distinct
// (exe, parent_exe) 回调 firstseen。
// panic 按 M3 契约隔离（R8.4 复审 F-001）：本函数跑在实现自有的 worker
// goroutine 里，一树 panic 不恢复会击穿整个进程——恢复、计入 panics、
// 丢弃当前树后继续消费后续树（范式同 rules.Engine.process 的 per-job
// recover；树已从内存摘除，丢弃即丢失该树证据，内存上界优先）。
func (h *Handler) archive(t *tree) {
	defer func() {
		if r := recover(); r != nil {
			h.panics.Add(1)
			slog.Error("session archive panic recovered, tree dropped", "host", t.host, "root_pid", t.root.pid, "panic", r)
		}
	}()
	trow, nodes := treeRows(t)
	if h.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := h.store.SaveTree(ctx, trow, nodes)
		cancel()
		if err != nil {
			h.archiveFailed.Add(1)
			slog.Error("session tree archive failed, dropped", "host", t.host, "root_pid", t.root.pid, "nodes", len(nodes), "err", err)
		} else {
			h.treesArchived.Add(1)
			h.nodesArchived.Add(uint64(len(nodes)))
		}
	}
	if h.parent != nil {
		for _, p := range parentExePairs(t) {
			h.parent.RegisterParentExe(context.Background(), t.host, t.agentID, p[0], p[1], t.lastTsMs)
		}
	}
}

// treeRows 把树定格为归档行。first/last 取树内最小/最大事件时间。
func treeRows(t *tree) (*TreeRow, []NodeRow) {
	tr := &TreeRow{
		Host:           t.host,
		AgentID:        t.agentID,
		BootID:         t.bootID,
		RootPid:        int32(t.root.pid),
		RootStartTicks: int64(t.root.startTicks),
		FirstTsMs:      t.root.firstTsMs,
		LastTsMs:       t.root.lastTsMs,
	}
	exes := make(map[string]struct{})
	var nodes []NodeRow
	var walk func(n *node)
	walk = func(n *node) {
		nodes = append(nodes, NodeRow{
			Pid:        int32(n.pid),
			StartTicks: int64(n.startTicks),
			ParentPid:  int32(n.parentPid),
			Exe:        n.exe,
			Argv:       n.argv,
			FirstTsMs:  n.firstTsMs,
			LastTsMs:   n.lastTsMs,
			Exited:     !n.live,
		})
		if n.exe != "" {
			exes[n.exe] = struct{}{}
		}
		if n.firstTsMs < tr.FirstTsMs {
			tr.FirstTsMs = n.firstTsMs
		}
		if n.lastTsMs > tr.LastTsMs {
			tr.LastTsMs = n.lastTsMs
		}
		for _, c := range n.children {
			walk(c)
		}
	}
	walk(t.root)
	tr.NodeCount = len(nodes)
	tr.Exes = make([]string, 0, len(exes))
	for e := range exes {
		tr.Exes = append(tr.Exes, e)
	}
	sort.Strings(tr.Exes)
	return tr, nodes
}
