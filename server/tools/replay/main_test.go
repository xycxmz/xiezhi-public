// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/xycxmz/xiezhi-public/proto"
	"github.com/xycxmz/xiezhi-public/server/internal/firstseen"
	"github.com/xycxmz/xiezhi-public/server/internal/pipeline"
	"github.com/xycxmz/xiezhi-public/server/internal/rules"
)

func evExecve(ts uint64, exe string) *pb.Event {
	return &pb.Event{Header: &pb.EventHeader{AgentId: "ag1", Hostname: "h1", TsMs: ts, EventType: pb.EventType_EXECVE},
		Body: &pb.Event_Execve{Execve: &pb.ExecveEvent{Proc: &pb.ProcessContext{Pid: 7, Exe: exe}}}}
}

func evConnect(ts uint64, ip []byte, port uint32) *pb.Event {
	return &pb.Event{Header: &pb.EventHeader{AgentId: "ag1", Hostname: "h2", TsMs: ts, EventType: pb.EventType_CONNECT},
		Body: &pb.Event_Net{Net: &pb.NetEvent{Proc: &pb.ProcessContext{Pid: 7}, Ip: ip, Port: port}}}
}

func obsOf(t *testing.T, ev *pb.Event) firstseen.Obs {
	t.Helper()
	ks := firstseen.ExtractKeys(ev)
	if len(ks) != 1 {
		t.Fatalf("ExtractKeys = %d obs, want 1", len(ks))
	}
	return ks[0]
}

func TestMemFSStoreReportsNewKeyOnce(t *testing.T) {
	m := newMemStore()
	k1 := obsOf(t, evExecve(1, "/tmp/a"))
	k2 := obsOf(t, evExecve(1, "/tmp/b"))
	idx, err := m.Upsert(context.Background(), []firstseen.Obs{k1, k2})
	if err != nil || len(idx) != 2 {
		t.Fatalf("first upsert idx = %v, err = %v", idx, err)
	}
	idx, err = m.Upsert(context.Background(), []firstseen.Obs{k1, k2})
	if err != nil || len(idx) != 0 {
		t.Fatalf("repeat upsert idx = %v, err = %v (want no new)", idx, err)
	}
	got := m.obsInOrder()
	if len(got) != 2 || got[0].Key != k1.Key || got[1].Key != k2.Key {
		t.Fatalf("obsInOrder = %+v", got)
	}
}

func TestTallyRuleHits(t *testing.T) {
	alerts := []pipeline.Alert{
		{RuleID: "nmap-syn"}, {RuleID: "nmap-syn"}, {RuleID: "curl-bash"},
	}
	m := tallyRuleHits(alerts)
	if len(m) != 2 || m["nmap-syn"] != 2 || m["curl-bash"] != 1 {
		t.Fatalf("tally = %v", m)
	}
}

func TestTopNDeterministicOrder(t *testing.T) {
	in := map[string]int{"b": 5, "a": 5, "c": 9, "d": 1}
	got := topN(in, 3)
	want := []kv{{"c", 9}, {"a", 5}, {"b", 5}}
	if len(got) != 3 {
		t.Fatalf("topN len = %d", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("topN = %v, want %v (value desc, key asc tiebreak)", got, want)
		}
	}
}

func TestClassifyObs(t *testing.T) {
	obs := []firstseen.Obs{
		obsOf(t, evExecve(1, "/usr/bin/curl")),  // 白名单
		obsOf(t, evExecve(1, "/usr/bin/vi")),    // 白名单
		obsOf(t, evExecve(1, "/tmp/miner")),     // 白名单外
		obsOf(t, evConnect(1, []byte{1, 2, 3, 4}, 443)),
	}
	wl, byKind, byHost := classifyObs(obs, []string{"/usr"})
	if wl != 2 {
		t.Fatalf("whitelisted exe = %d, want 2", wl)
	}
	if byKind["exe"] != 3 || byKind["conn_target"] != 1 {
		t.Fatalf("byKind = %v", byKind)
	}
	if byHost["h1"] != 3 || byHost["h2"] != 1 {
		t.Fatalf("byHost = %v", byHost)
	}
}

func TestRenderReport(t *testing.T) {
	rep := newReport()
	rep.From = time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	rep.To = time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	rep.Limit = 100
	rep.Events = 150
	rep.agents["a1"] = struct{}{}
	rep.agents["a2"] = struct{}{}
	rep.Types = map[string]int{"EXECVE": 100, "CONNECT": 50}
	rep.FeedElapsed = 1500 * time.Millisecond
	rep.RulesEnabled = true
	rep.RulesStats = rules.Stats{RulesLoaded: 8, Version: "abc123", EventsProcessed: 150, AlertsEmitted: 13}
	rep.RuleHits = map[string]int{"nmap-syn": 12, "curl-bash": 1}
	rep.FSObs = make([]firstseen.Obs, 3)
	rep.FSWhitelisted = 1
	rep.FSByKind = map[string]int{"exe": 2, "conn_target": 1}
	rep.FSByHost = map[string]int{"h1": 3}
	rep.FSDigestAlerts = 2

	var buf bytes.Buffer
	if err := renderReport(&buf, rep); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"# HIDS 回放评测报告",
		"- 事件: 150（已达 LIMIT 100",
		"| nmap-syn | 12 |",
		"| curl-bash | 1 |",
		"- 键 3（白名单内 exe 1：生产只记录不告警）",
		"| conn_target | 1 |",
		"| EXECVE | 100 |",
		"| 主机 | 新键数 |",
		"| h1 | 3 |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q\n---\n%s", want, out)
		}
	}

	// 规则未启用分支
	rep2 := newReport()
	rep2.Types = map[string]int{}
	var buf2 bytes.Buffer
	if err := renderReport(&buf2, rep2); err != nil {
		t.Fatalf("render empty: %v", err)
	}
	if !strings.Contains(buf2.String(), "未启用（-rules 为空）") || !strings.Contains(buf2.String(), "（无数据）") {
		t.Errorf("disabled-rules report wrong:\n%s", buf2.String())
	}
}
