// SPDX-License-Identifier: Apache-2.0

package session

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

// exe/argv 按字段截 256B（内存上界 + PG 行宽双重考虑）。截断退到 rune 边界；
// argv/exe 是攻击者可控输入，先清非法 UTF-8，否则整条 PG 写入会失败。
const (
	maxExeBytes  = 256
	maxArgvBytes = 256
)

// node 是进程树节点。活跃与归档解耦：EXIT 后 live=false 进「墓园」——pid 槽
// 位立即释放（防复用错配），但节点保留在树内随整树归档（退出的短命进程恰是
// LLM 研判的高价值证据，不能丢）。
type node struct {
	pid        uint32
	startTicks uint64
	exe        string
	argv       string
	parentPid  uint32
	parent     *node
	children   []*node
	tree       *tree
	live       bool
	firstTsMs  int64
	lastTsMs   int64
}

// tree 是一个归档单元：原始根 + 全部后代（含墓园）。活跃时钟用服务端到达
// 时间（免 agent 钟漂）；lastTsMs 是事件时钟的最大值（回填 firstseen 用）。
// liveCount==0（整树退出）即时归档。
type tree struct {
	root       *node
	host       string
	agentID    string
	bootID     string
	liveCount  int
	lastActive time.Time
	lastTsMs   int64
}

func (t *tree) touch(now time.Time, tsMs int64) {
	if now.After(t.lastActive) {
		t.lastActive = now
	}
	if tsMs > t.lastTsMs {
		t.lastTsMs = tsMs
	}
}

// hostTree 是单主机的进程森林。byPid 只放活节点（EXIT 必须释放 pid 槽位）；
// lastByPid 记每个 pid 最近一次化身（含墓园），父进程 EXIT 后才 fork 出的
// 子进程靠它挂到正确的父节点上，不会凭空复制父节点。
type hostTree struct {
	host         string
	agentID      string
	bootID       string
	stats        *stats
	byPid        map[uint32]*node
	lastByPid    map[uint32]*node
	trees        []*tree
	maxNodes     int // 写路径硬上界：新建节点前须腾位（内存上界是硬要求，不等 sweep）
	nodeCount    int // 活 + 墓园，内存上界判据
	pendingEvict []*tree // 写路径驱逐、待上层锁外归档的树
}

func newHostTree(host, agentID, bootID string, maxNodes int, st *stats) *hostTree {
	return &hostTree{
		host:      host,
		agentID:   agentID,
		bootID:    bootID,
		stats:     st,
		byPid:     make(map[uint32]*node),
		lastByPid: make(map[uint32]*node),
		maxNodes:  maxNodes,
	}
}

// atCap 报告节点数已达单主机上界。
func (ht *hostTree) atCap() bool {
	return ht.maxNodes > 0 && ht.nodeCount >= ht.maxNodes
}

// makeRoom 为新建节点腾位置：已达上界时驱逐最旧整树（与 sweepOnce 同款纪律：
// 记入 evictedRoots、清索引、进 pendingEvict 由 Handle 锁外归档）。skip 指明
// 本次操作正要写入的树，不驱；无可驱树（如单棵树打满）返回 false，调用方拒建。
func (ht *hostTree) makeRoom(skip *tree) bool {
	if !ht.atCap() {
		return true
	}
	oldest := -1
	for i, t := range ht.trees {
		if t == skip {
			continue
		}
		if oldest < 0 || t.lastActive.Before(ht.trees[oldest].lastActive) {
			oldest = i
		}
	}
	if oldest < 0 {
		return false
	}
	t := ht.trees[oldest]
	ht.trees = append(ht.trees[:oldest], ht.trees[oldest+1:]...)
	ht.detachTreeIndexes(t)
	ht.pendingEvict = append(ht.pendingEvict, t)
	ht.stats.evictedRoots.Add(1)
	return true
}

func (ht *hostTree) index(n *node) {
	ht.byPid[n.pid] = n
	ht.lastByPid[n.pid] = n
}

// orphanFromProc 为无 FORK 前史的进程（早于 agent 启动的存量，或复用 pid 的
// 新化身）建孤立根并成树。exe/argv 即时消毒截断。
func (ht *hostTree) orphanFromProc(p *pb.ProcessContext, tsMs int64, now time.Time) *node {
	if !ht.makeRoom(nil) {
		ht.stats.nodeCapDrops.Add(1)
		return nil
	}
	n := &node{
		pid:        p.GetPid(),
		startTicks: p.GetStartTicks(),
		exe:        sanitize(p.GetExe(), maxExeBytes),
		argv:       sanitize(strings.Join(p.GetArgv(), " "), maxArgvBytes),
		parentPid:  p.GetPpid(),
		live:       true,
		firstTsMs:  tsMs,
		lastTsMs:   tsMs,
	}
	t := &tree{root: n, host: ht.host, agentID: ht.agentID, bootID: ht.bootID, liveCount: 1, lastActive: now, lastTsMs: tsMs}
	n.tree = t
	ht.index(n)
	ht.trees = append(ht.trees, t)
	ht.nodeCount++
	return n
}

func (ht *hostTree) attachChild(pn *node, childPid uint32, childTicks uint64, tsMs int64, now time.Time) {
	if !ht.makeRoom(pn.tree) {
		ht.stats.nodeCapDrops.Add(1)
		return
	}
	cn := &node{
		pid:        childPid,
		startTicks: childTicks,
		parentPid:  pn.pid,
		parent:     pn,
		tree:       pn.tree,
		live:       true,
		firstTsMs:  tsMs,
		lastTsMs:   tsMs,
	}
	pn.children = append(pn.children, cn)
	pn.tree.liveCount++
	pn.tree.touch(now, tsMs)
	ht.index(cn)
	ht.nodeCount++
}

// fork 建边 (parent → child)。返回值非 nil = 期间有整树退空，需即时归档。
func (ht *hostTree) fork(parent *pb.ProcessContext, childPid uint32, childTicks uint64, tsMs int64, now time.Time) *tree {
	if parent == nil || parent.GetPid() == 0 || childPid == 0 {
		return nil
	}
	var done *tree
	if live, ok := ht.byPid[childPid]; ok {
		// child 槽位还挂着活节点 = 漏了它的 EXIT（内核侧 pid 已被复用）
		ht.stats.pidCollision.Add(1)
		done = ht.detachLive(live, tsMs, now)
	}
	pn := ht.byPid[parent.GetPid()]
	if pn == nil {
		pn = ht.lastByPid[parent.GetPid()]
	}
	if pn == nil {
		pn = ht.orphanFromProc(parent, tsMs, now)
		if pn == nil {
			return done // 已达节点上界：拒建孤立根
		}
	}
	ht.attachChild(pn, childPid, childTicks, tsMs, now)
	return done
}

// execve 按 pid 补 exe/argv；找不到活节点建孤立根。返回值非 nil = 整树退空。
//
// pid 复用已知风险（brief 声明）：LKM 线 EXECVE 事件不带 start_ticks（恒 0），
// 只能按 pid 匹配——若内核已复用 pid 而我们漏收 EXIT，本次 execve 会错配到
// 旧化身节点上。M4 eBPF 线补齐 start_ticks 后，下面的 ticks 双非零硬判定
// 分支即自动收紧为精确匹配。
func (ht *hostTree) execve(p *pb.ProcessContext, tsMs int64, now time.Time) *tree {
	if p == nil || p.GetPid() == 0 {
		return nil
	}
	pid, ticks := p.GetPid(), p.GetStartTicks()
	if n, ok := ht.byPid[pid]; ok {
		if ticks != 0 && n.startTicks != 0 && ticks != n.startTicks {
			ht.stats.pidCollision.Add(1)
			done := ht.detachLive(n, tsMs, now)
			ht.orphanFromProc(p, tsMs, now)
			return done
		}
		if n.startTicks == 0 {
			n.startTicks = ticks
		}
		if exe := sanitize(p.GetExe(), maxExeBytes); exe != "" {
			n.exe = exe
		}
		n.argv = sanitize(strings.Join(p.GetArgv(), " "), maxArgvBytes)
		if n.lastTsMs < tsMs {
			n.lastTsMs = tsMs
		}
		n.tree.touch(now, tsMs)
		return nil
	}
	ht.orphanFromProc(p, tsMs, now)
	return nil
}

// exit 按 pid 摘节点进墓园。返回值非 nil = 整树退空，需即时归档。
// ticks 双非零且不等 = 上一化身/从未见过的化身的迟到 EXIT，跳过。
func (ht *hostTree) exit(pid uint32, ticks uint64, tsMs int64, now time.Time) *tree {
	n, ok := ht.byPid[pid]
	if !ok {
		ht.stats.unknownExit.Add(1) // 未知 EXIT：未见过的 fork、乱序或迟到事件
		return nil
	}
	if ticks != 0 && n.startTicks != 0 && ticks != n.startTicks {
		ht.stats.unknownExit.Add(1)
		return nil
	}
	if n.startTicks == 0 {
		n.startTicks = ticks
	}
	return ht.detachLive(n, tsMs, now)
}

// detachLive 把活节点转入墓园：释放 pid 槽位、保留树内挂接。整树退空时把树
// 从森林摘除并返回，交给上层归档。
func (ht *hostTree) detachLive(n *node, tsMs int64, now time.Time) *tree {
	n.live = false
	if n.lastTsMs < tsMs {
		n.lastTsMs = tsMs
	}
	delete(ht.byPid, n.pid)
	t := n.tree
	t.liveCount--
	t.touch(now, tsMs)
	if t.liveCount == 0 {
		ht.detachTree(t)
		return t
	}
	return nil
}

// detachTreeIndexes 清整树的索引与节点计数，不动 trees 切片与节点内容——
// 此刻节点集已经完整，随后整体落 PG。切片由调用方管理（过滤/驱逐各取所需）。
func (ht *hostTree) detachTreeIndexes(t *tree) {
	var walk func(n *node)
	walk = func(n *node) {
		if n.live {
			delete(ht.byPid, n.pid)
		}
		// C-3：pid 复用后 lastByPid 已指向新化身所在树，无条件 delete 会
		// 击穿墓园回落与 fork 父回落——仅当仍指向本节点才删。
		if cur, ok := ht.lastByPid[n.pid]; ok && cur == n {
			delete(ht.lastByPid, n.pid)
		}
		ht.nodeCount--
		for _, c := range n.children {
			walk(c)
		}
	}
	walk(t.root)
}

// detachTree = 索引清理 + 从 trees 切片移除，整树退出路径用。
func (ht *hostTree) detachTree(t *tree) {
	ht.detachTreeIndexes(t)
	for i, x := range ht.trees {
		if x == t {
			ht.trees = append(ht.trees[:i], ht.trees[i+1:]...)
			break
		}
	}
}

// touch 刷新节点与树的活动时钟（任何带 ProcessContext 的事件都算活动）。
// 未知 pid 静默忽略：多数是早于 agent 的存量进程、从未 execve 过。
func (ht *hostTree) touch(pid uint32, tsMs int64, now time.Time) {
	n, ok := ht.byPid[pid]
	if !ok {
		return
	}
	if n.lastTsMs < tsMs {
		n.lastTsMs = tsMs
	}
	n.tree.touch(now, tsMs)
}

// sanitize 先清非法 UTF-8 再按 rune 边界截断。
func sanitize(s string, limit int) string {
	if len(s) > limit || !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// renderSubtree 序列化为缩进树文本（每级 2 空格，墓园节点标 [exited]）。
// depth 语义：<0 整棵子树，0 仅本节点，n 向下 n 层。
func renderSubtree(n *node, depth int) string {
	var b strings.Builder
	var walk func(n *node, level int)
	walk = func(n *node, level int) {
		if depth >= 0 && level > depth {
			return
		}
		b.WriteString(strings.Repeat("  ", level))
		fmt.Fprintf(&b, "pid=%d exe=%s argv=%q", n.pid, n.exe, n.argv)
		if !n.live {
			b.WriteString(" [exited]")
		}
		b.WriteByte('\n')
		for _, c := range n.children {
			walk(c, level+1)
		}
	}
	walk(n, 0)
	return b.String()
}

// parentExePairs 收集树内 distinct (exe, parent_exe) 组合，排序保证回调顺序
// 确定。父链上 exe 未知的节点跳过（早于 agent 的存量根）。已知局限：节点
// 多次 execve 换镜像时，只记录归档时刻的最终镜像配对。
func parentExePairs(t *tree) [][2]string {
	seen := make(map[[2]string]struct{})
	var out [][2]string
	var walk func(n *node)
	walk = func(n *node) {
		if n.exe != "" && n.parent != nil && n.parent.exe != "" {
			k := [2]string{n.exe, n.parent.exe}
			if _, ok := seen[k]; !ok {
				seen[k] = struct{}{}
				out = append(out, k)
			}
		}
		for _, c := range n.children {
			walk(c)
		}
	}
	walk(t.root)
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}

// rebuildNodes 从 PG 行重建树并返回锚定 pid 的最近化身节点。按
// (first_ts_ms, pid) 排序后单遍缝合：parent 取同 pid 已建节点的最新一个。
// 树内 pid 复用（同树两代同 pid）时父子归属是启发式，M3 接受。
func rebuildNodes(rows []NodeRow, anchorPid uint32) *node {
	sorted := make([]NodeRow, len(rows))
	copy(sorted, rows)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].FirstTsMs != sorted[j].FirstTsMs {
			return sorted[i].FirstTsMs < sorted[j].FirstTsMs
		}
		return sorted[i].Pid < sorted[j].Pid
	})
	last := make(map[uint32]*node, len(sorted))
	var anchor *node
	for _, r := range sorted {
		n := &node{
			pid:        uint32(r.Pid),
			startTicks: uint64(r.StartTicks),
			exe:        r.Exe,
			argv:       r.Argv,
			parentPid:  uint32(r.ParentPid),
			live:       !r.Exited,
			firstTsMs:  r.FirstTsMs,
			lastTsMs:   r.LastTsMs,
		}
		if r.ParentPid != 0 {
			if p, ok := last[uint32(r.ParentPid)]; ok {
				n.parent = p
				p.children = append(p.children, n)
			}
		}
		last[n.pid] = n
		if n.pid == anchorPid {
			anchor = n
		}
	}
	return anchor
}
