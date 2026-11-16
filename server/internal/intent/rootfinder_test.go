// SPDX-License-Identifier: Apache-2.0

package intent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/xycxmz/xiezhi-public/proto"
	"github.com/xycxmz/xiezhi-public/server/internal/session"
)

// R4.3 桶键升级的确定性验收（审计「已接线未验证」项）：
// 同一会话树内跨 uid（sudo/setpriv 提权链形态）标签分必须合桶累计，
// (host, uid) 回落模式下同样的分数会因 uid 拆散而漏判。
const rootFinderPolicy = `
tags:
  cred_material_read: 4.0
  data_upload: 3.0
threshold: 8.0
`

func rfHdr(t pb.EventType, ts uint64) *pb.EventHeader {
	return &pb.EventHeader{AgentId: "ag1", Hostname: "h1", BootId: "b1", TsMs: ts, EventType: t}
}

func rfExec(ts uint64, pid, ppid, uid uint32, argv ...string) *pb.Event {
	return &pb.Event{Header: rfHdr(pb.EventType_EXECVE, ts), Body: &pb.Event_Execve{Execve: &pb.ExecveEvent{
		Proc: &pb.ProcessContext{Pid: pid, Ppid: ppid, Exe: argv[0], Argv: argv, Uid: uid, StartTicks: 1},
	}}}
}

// 喂同一事件流给 session（建树）与 intent（打分入桶），模拟 main.go 的
// handler 装配顺序（fs → session → intent）。
func feedBoth(ss *session.Handler, ih *Handler, evs ...*pb.Event) {
	for _, ev := range evs {
		ss.Handle(context.Background(), ev)
		ih.Handle(context.Background(), ev)
	}
}

// 同 main.go 的 rootFinderAdapter：session.RootFinder 与 intent.RootFinder
// 结构同型不同包，经直通转换桥接。
type rfAdapter struct{ rf session.RootFinder }

func (a rfAdapter) FindRoot(host string, pid int32) (SessionRoot, bool) {
	r, ok := a.rf.FindRoot(host, pid)
	if !ok {
		return SessionRoot{}, false
	}
	return SessionRoot{RootPid: r.RootPid, RootTicks: r.RootTicks, RootExe: r.RootExe}, true
}

func TestRootFinderMergesUidSwitchWithinTree(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writePolicy(t, path, rootFinderPolicy)

	ss := session.New(nil, nil, session.Config{})
	defer ss.Close()

	s := &fakeSink{}
	ih, err := New(NewBuiltin(), s, path, WithPollInterval(time.Hour), WithRootFinder(rfAdapter{rf: ss.RootFinder()}))
	if err != nil {
		t.Fatal(err)
	}
	defer ih.Close()

	ts := uint64(1731400000000)
	fork := &pb.Event{Header: rfHdr(pb.EventType_FORK, ts), Body: &pb.Event_Fork{Fork: &pb.ForkEvent{
		Parent: &pb.ProcessContext{Pid: 100, Ppid: 1, Exe: "/bin/bash"}, ChildPid: 200, ChildStartTicks: 1,
	}}}
	rootCmd := append([]string{"bash", "-c"},
		"cat /root/.ssh/id_rsa > /dev/null; setpriv --reuid=1700 scp /etc/hosts w3@127.0.0.1:/tmp/")
	feedBoth(ss, ih,
		fork,
		rfExec(ts+10, 100, 1, 0, rootCmd...), // 树根 uid=0：cred 4.0 + upload 3.0
		rfExec(ts+20, 200, 100, 1700, "setpriv", "--reuid=1700",
			"scp", "/etc/hosts", "w3@127.0.0.1:/tmp/"), // 树内 uid=1700：upload 3.0
	)

	if r, ok := ss.RootFinder().FindRoot("h1", 100); !ok {
		t.Fatalf("FindRoot(h1,100) not found; tree missing")
	} else if r.RootPid != 100 {
		t.Fatalf("FindRoot(h1,100) root=%d, want 100", r.RootPid)
	}
	if r, ok := ss.RootFinder().FindRoot("h1", 200); !ok || r.RootPid != 100 {
		t.Fatalf("FindRoot(h1,200)=%+v ok=%v, want root=100", r, ok)
	}

	// 短命进程竞态（线上 A3 形态）：EXECVE 刚过、EXIT 已把节点摘出活索引，
	// 而 intent worker 异步处理才来查——必须经墓园（lastByPid）回落命中。
	exitEv := &pb.Event{Header: rfHdr(pb.EventType_EXIT, ts+30), Body: &pb.Event_Exit{Exit: &pb.ExitEvent{
		Pid: 200, StartTicks: 1,
	}}}
	ss.Handle(context.Background(), exitEv)
	if r, ok := ss.RootFinder().FindRoot("h1", 200); !ok || r.RootPid != 100 {
		t.Fatalf("FindRoot(h1,200) after exit=%+v ok=%v, want root=100 (graveyard fallback)", r, ok)
	}

	waitUntil(t, 2*time.Second, func() bool {
		return len(s.snapshot()) == 1
	}, "root 模式跨 uid 合桶告警")
	if a := s.snapshot()[0]; a.Severity != "high" {
		t.Errorf("跨 uid 合桶告警 severity = %s, want high", a.Severity)
	}
}

// 占位锚点不得越过（四轮实测教训）：fork 建的 parent 占位无 exec，越过它
// 会把无关会话（sshd/systemd 锚点）并成一棵桶树。爬树停在最后一个有 exe
// 的祖先——同一 shell 会话（含 sudo/setuid 链）同桶，会话之间分桶。
func TestRootFinderStopsAtPlaceholderAnchor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writePolicy(t, path, rootFinderPolicy)

	ss := session.New(nil, nil, session.Config{})
	defer ss.Close()

	ts := uint64(1731400000000)
	// 占位锚（无 exe 的 fork parent，pid 900）→ 实体 bash（100）→ scp（200）。
	fork := &pb.Event{Header: rfHdr(pb.EventType_FORK, ts), Body: &pb.Event_Fork{Fork: &pb.ForkEvent{
		Parent: &pb.ProcessContext{Pid: 900, Ppid: 1}, ChildPid: 100, ChildStartTicks: 1,
	}}}
	innerFork := &pb.Event{Header: rfHdr(pb.EventType_FORK, ts+1), Body: &pb.Event_Fork{Fork: &pb.ForkEvent{
		Parent: &pb.ProcessContext{Pid: 100, Ppid: 900, Exe: "/bin/bash"}, ChildPid: 200, ChildStartTicks: 1,
	}}}
	ss.Handle(context.Background(), fork)
	ss.Handle(context.Background(), innerFork)
	ss.Handle(context.Background(), rfExec(ts+2, 100, 900, 0, "bash", "-c", "cmd"))
	ss.Handle(context.Background(), rfExec(ts+3, 200, 100, 1700, "scp", "/etc/hosts", "w@127.0.0.1:/tmp/"))

	if r, ok := ss.RootFinder().FindRoot("h1", 200); !ok || r.RootPid != 100 {
		t.Fatalf("FindRoot(h1,200)=%+v ok=%v, want root=100 (stop at entity, not placeholder 900)", r, ok)
	}
}

// 对照组：无 RootFinder（legacy (host, uid) 桶键）下同样的事件流零告警，
// 证明上面的告警确实来自桶键升级而非分数本身足够。
func TestLegacyBucketsSplitOnUidSwitch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(rootFinderPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &fakeSink{}
	ih, err := New(NewBuiltin(), s, path, WithPollInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer ih.Close()

	ts := uint64(1731400000000)
	rootCmd := append([]string{"bash", "-c"},
		"cat /root/.ssh/id_rsa > /dev/null; setpriv --reuid=1700 scp /etc/hosts w3@127.0.0.1:/tmp/")
	ih.Handle(context.Background(), rfExec(ts+10, 100, 1, 0, rootCmd...))
	ih.Handle(context.Background(), rfExec(ts+20, 200, 100, 1700, "setpriv", "--reuid=1700",
		"scp", "/etc/hosts", "w3@127.0.0.1:/tmp/"))

	time.Sleep(200 * time.Millisecond)
	if got := len(s.snapshot()); got != 0 {
		t.Errorf("legacy 模式 uid 拆分下不应告警, got %d alerts", got)
	}
}
