// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
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

const canonicalRule = `id: exec-recon-nmap
type: field
event: EXECVE
severity: medium
mitre: T1046
match:
  logic: and
  conditions:
    - op: EQU
      field: execve.proc.argv.0
      value: nmap
    - op: REGEX
      field: execve.proc.argv
      value: '-s[ST]|-A|--script'
action: alert
`

const netHighPortRule = `id: net-high-port
type: field
event: CONNECT
severity: high
match:
  logic: and
  conditions:
    - op: MT
      field: net.port
      value: '1024'
action: alert
`

type fakeSink struct {
	mu          sync.Mutex
	alerts      []*pipeline.Alert
	gate        chan struct{}
	panicOnCall int32
	calls       atomic.Int32
}

func (s *fakeSink) EmitAlert(_ context.Context, a *pipeline.Alert) {
	if n := s.calls.Add(1); int32(n) == s.panicOnCall {
		panic("sink boom")
	}
	if s.gate != nil {
		<-s.gate
	}
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

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func hdr(et pb.EventType) *pb.EventHeader {
	return &pb.EventHeader{AgentId: "agent-1", Hostname: "host-1", TsMs: 1731400000123, EventType: et}
}

func evNmap() *pb.Event {
	return &pb.Event{Header: hdr(pb.EventType_EXECVE), Body: &pb.Event_Execve{Execve: &pb.ExecveEvent{
		Proc: &pb.ProcessContext{
			Argv:   []string{"nmap", "-sS", "10.0.0.0/8"},
			Exe:    "/usr/bin/nmap",
			Uid:    0,
			EnvSel: map[string]string{"LD_PRELOAD": "/tmp/x.so"},
		},
	}}}
}

func evNmapBigArgv(big string) *pb.Event {
	return &pb.Event{Header: hdr(pb.EventType_EXECVE), Body: &pb.Event_Execve{Execve: &pb.ExecveEvent{
		Proc: &pb.ProcessContext{Argv: []string{"nmap", "-sS", big}},
	}}}
}

func evNet(port uint32) *pb.Event {
	return &pb.Event{Header: hdr(pb.EventType_CONNECT), Body: &pb.Event_Net{Net: &pb.NetEvent{Op: "connect", Port: port}}}
}

func evDNS() *pb.Event {
	return &pb.Event{Header: hdr(pb.EventType_DNS_QUERY), Body: &pb.Event_Dns{Dns: &pb.DnsEvent{
		Queries: []string{"evil.example.com", "cdn.example.com"}, ServerPort: 53,
	}}}
}

func evCred() *pb.Event {
	return &pb.Event{Header: hdr(pb.EventType_CRED_CHANGE), Body: &pb.Event_Cred{Cred: &pb.CredEvent{OldUid: 1000, NewUid: 0}}}
}

// condRule 拼一条单条件规则；elemLogic 非空时追加元素间 logic。
func condRule(event, logic, op, field, value, elemLogic string) string {
	el := ""
	if elemLogic != "" {
		el = "\n      logic: " + elemLogic
	}
	return fmt.Sprintf(`id: t
type: field
event: %s
severity: low
match:
  logic: %s
  conditions:
    - op: %s
      field: %s
      value: '%s'%s
action: alert`, event, logic, op, field, value, el)
}

func matchEvent(t *testing.T, ruleSrc string, ev *pb.Event) (bool, string) {
	t.Helper()
	raw, err := parseRuleYAML([]byte(ruleSrc))
	if err != nil {
		t.Fatalf("解析规则失败: %v", err)
	}
	cr, err := compileRule(raw)
	if err != nil {
		t.Fatalf("编译规则失败: %v", err)
	}
	root, _, err := eventRoot(ev)
	if err != nil {
		t.Fatalf("protojson 失败: %v", err)
	}
	return cr.matches(root)
}

// TestProtojsonShape 钉死路径语义的地基：camelCase 键、枚举名、数字=float64、
// EmitUnpopulated 使零值字段可匹配、未设置的 oneof 分支不出现。
func TestProtojsonShape(t *testing.T) {
	root, _, err := eventRoot(evNmap())
	if err != nil {
		t.Fatal(err)
	}
	h, ok := root["header"].(map[string]any)
	if !ok {
		t.Fatalf("header 不是对象: %T", root["header"])
	}
	if h["agentId"] != "agent-1" || h["eventType"] != "EXECVE" {
		t.Fatalf("header 键语义变化: %v", h)
	}
	// protojson 把 64 位整数序列化为十进制字符串，uint32 是数字：钉死这点。
	if h["seq"] != "0" || h["tsMs"] != "1731400000123" {
		t.Fatalf("64 位整数应为字符串, 得到 seq=%#v tsMs=%#v", h["seq"], h["tsMs"])
	}
	ex, ok := root["execve"].(map[string]any)
	if !ok {
		t.Fatalf("execve 分支缺失")
	}
	proc := ex["proc"].(map[string]any)
	argv, ok := proc["argv"].([]any)
	if !ok || len(argv) != 3 || argv[0] != "nmap" || argv[2] != "10.0.0.0/8" {
		t.Fatalf("argv 数组语义变化: %#v", proc["argv"])
	}
	if proc["uid"] != float64(0) {
		t.Fatalf("零值 uid 应可匹配, 得到 %#v", proc["uid"])
	}
	if ex["fromMemfd"] != false {
		t.Fatalf("零值布尔应出现, 得到 %#v", ex["fromMemfd"])
	}
	if _, present := root["net"]; present {
		t.Fatalf("未设置的 oneof 分支不应出现")
	}
}

func TestParseYAML(t *testing.T) {
	t.Run("接受规范形态", func(t *testing.T) {
		raw, err := parseRuleYAML([]byte(canonicalRule))
		if err != nil {
			t.Fatal(err)
		}
		if raw.id != "exec-recon-nmap" || raw.typ != "field" || raw.event != "EXECVE" ||
			raw.severity != "medium" || raw.mitre != "T1046" || raw.action != "alert" || raw.matchLogic != "and" {
			t.Fatalf("字段解析错误: %+v", raw)
		}
		if len(raw.conds) != 2 {
			t.Fatalf("条件数错误: %d", len(raw.conds))
		}
		c0, c1 := raw.conds[0], raw.conds[1]
		if c0.op != "EQU" || c0.field != "execve.proc.argv.0" || c0.value != "nmap" || c0.logic != "" {
			t.Fatalf("条件0错误: %+v", c0)
		}
		if c1.op != "REGEX" || c1.value != "-s[ST]|-A|--script" {
			t.Fatalf("条件1错误: %+v", c1)
		}
	})
	t.Run("引号与注释", func(t *testing.T) {
		src := `id: q
type: field
event: EXECVE
severity: low
match:
  logic: and
  conditions:
    - op: INCL
      field: execve.proc.exe
      value: "a: b #x"  # 行尾注释
    - op: EQU
      field: header.agentId
      value: 'it''s'
action: alert
`
		raw, err := parseRuleYAML([]byte(src))
		if err != nil {
			t.Fatal(err)
		}
		if raw.conds[0].value != "a: b #x" {
			t.Fatalf("双引号值错误: %q", raw.conds[0].value)
		}
		if raw.conds[1].value != "it's" {
			t.Fatalf("单引号转义错误: %q", raw.conds[1].value)
		}
	})
	rejects := []struct{ name, src string }{
		{"Tab 缩进", "id: x\n\ttype: field\n"},
		{"未知顶层键", "id: x\nfoo: 1\n"},
		{"顶层键重复", "id: x\nid: y\n"},
		{"裸值含冒号", "id: a: b\n"},
		{"引号未闭合", "id: 'x\n"},
		{"match 行内值", "match: {}\nid: x\n"},
		{"流式列表", "id: x\nmatch:\n  logic: and\n  conditions: [{op: EQU}]\n"},
		{"conditions 空块", "id: x\nmatch:\n  logic: and\n  conditions:\n"},
		{"condition 未知键", "id: x\nmatch:\n  logic: and\n  conditions:\n    - op: EQU\n      foo: 1\n"},
		{"空文件", "# 只有注释\n"},
		{"列表项缩进不齐", "id: x\nmatch:\n  logic: and\n  conditions:\n    - op: EQU\n       field: a.b\n"},
	}
	for _, tc := range rejects {
		t.Run("拒绝/"+tc.name, func(t *testing.T) {
			if _, err := parseRuleYAML([]byte(tc.src)); err == nil {
				t.Fatalf("期望解析错误, 却通过了: %q", tc.src)
			}
		})
	}
}

func TestCompileRejects(t *testing.T) {
	bad := map[string]string{
		"action 非法": `id: c
type: field
event: EXECVE
severity: low
match:
  logic: and
  conditions:
    - op: INCL
      field: execve.proc.exe
      value: x
action: notify
`,
		"match.logic 非法": `id: c
type: field
event: EXECVE
severity: low
match:
  logic: xor
  conditions:
    - op: INCL
      field: execve.proc.exe
      value: x
action: alert
`,
		"conditions 缺失": `id: c
type: field
event: EXECVE
severity: low
match:
  logic: and
action: alert
`,
		"value 缺失": `id: c
type: field
event: EXECVE
severity: low
match:
  logic: and
  conditions:
    - op: INCL
      field: execve.proc.exe
action: alert
`,
		"元素 logic 非法": `id: c
type: field
event: EXECVE
severity: low
match:
  logic: and
  conditions:
    - op: INCL
      field: execve.proc.argv
      value: x
      logic: maybe
action: alert
`,
		"路径空段": `id: c
type: field
event: EXECVE
severity: low
match:
  logic: and
  conditions:
    - op: INCL
      field: execve..exe
      value: x
action: alert
`,
	}
	for name, src := range bad {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "r.yaml"), src)
			res, err := loadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if res.rejected != 1 || res.set.total != 0 {
				t.Fatalf("期望拒绝 1 条, 得到 rejected=%d total=%d", res.rejected, res.set.total)
			}
		})
	}
	t.Run("重复 id 跨文件", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "a.yaml"), canonicalRule)
		writeFile(t, filepath.Join(dir, "b.yaml"), canonicalRule)
		res, err := loadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if res.set.total != 1 || res.rejected != 1 {
			t.Fatalf("期望 1 载入 1 拒绝, 得到 total=%d rejected=%d", res.set.total, res.rejected)
		}
	})
}

// TestLoadDirMixed 用包内 testdata（1 好 6 坏）验证坏规则跳过且不废整批。
func TestLoadDirMixed(t *testing.T) {
	e, err := New("testdata", &fakeSink{}, WithPollInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	st := e.Stats()
	if st.RulesLoaded != 1 || st.RulesRejected != 6 {
		t.Fatalf("期望 loaded=1 rejected=6, 得到 %+v", st)
	}
}

func TestEvalOps(t *testing.T) {
	andOK := `id: t
type: field
event: EXECVE
severity: low
match:
  logic: and
  conditions:
    - op: EQU
      field: execve.proc.argv.0
      value: nmap
    - op: REGEX
      field: execve.proc.argv
      value: '-s[ST]'
action: alert
`
	andMiss := `id: t
type: field
event: EXECVE
severity: low
match:
  logic: and
  conditions:
    - op: EQU
      field: execve.proc.argv.0
      value: nmap
    - op: INCL
      field: execve.proc.exe
      value: /tmp/
action: alert
`
	orHit := `id: t
type: field
event: EXECVE
severity: low
match:
  logic: or
  conditions:
    - op: INCL
      field: execve.proc.exe
      value: /tmp/
    - op: EQU
      field: execve.proc.argv.0
      value: nmap
action: alert
`
	cases := []struct {
		name    string
		rule    string
		ev      *pb.Event
		hit     bool
		descHas string
	}{
		{"EQU 字符串命中", condRule("EXECVE", "and", "EQU", "header.agentId", "agent-1", ""), evNmap(), true, "header.agentId=agent-1"},
		{"EQU 数字自动分派", condRule("CONNECT", "and", "EQU", "net.port", "443", ""), evNet(443), true, "net.port=443"},
		{"EQU 数字未中", condRule("CONNECT", "and", "EQU", "net.port", "443", ""), evNet(8443), false, ""},
		{"EQU 零值字段可匹配", condRule("CRED_CHANGE", "and", "EQU", "cred.newUid", "0", ""), evCred(), true, "cred.newUid=0"},
		{"EQU 布尔", condRule("EXECVE", "and", "EQU", "execve.fromMemfd", "false", ""), evNmap(), true, "execve.fromMemfd=false"},
		{"NEQ 可比命中", condRule("CONNECT", "and", "NEQ", "net.op", "bind", ""), evNet(443), true, "net.op=connect"},
		{"NEQ 类型不匹配不命中", condRule("CONNECT", "and", "NEQ", "net.port", "abc", ""), evNet(443), false, ""},
		{"NEQ 缺字段不命中", condRule("EXECVE", "and", "NEQ", "execve.proc.argv.9", "zz", ""), evNmap(), false, ""},
		{"INCL 标量命中", condRule("EXECVE", "and", "INCL", "execve.proc.exe", "nmap", ""), evNmap(), true, "execve.proc.exe=/usr/bin/nmap"},
		{"INCL 标量未中", condRule("EXECVE", "and", "INCL", "execve.proc.exe", "/tmp/", ""), evNmap(), false, ""},
		{"INCL 数组 any 默认", condRule("DNS_QUERY", "and", "INCL", "dns.queries", "evil", ""), evDNS(), true, "dns.queries[0]=evil.example.com"},
		{"INCL 数组 all 全含", condRule("DNS_QUERY", "and", "INCL", "dns.queries", "example", "all"), evDNS(), true, "dns.queries[*]"},
		{"INCL 数组 all 非全含", condRule("DNS_QUERY", "and", "INCL", "dns.queries", "evil", "all"), evDNS(), false, ""},
		{"START 前缀", condRule("EXECVE", "and", "START", "execve.proc.exe", "/usr/bin/", ""), evNmap(), true, ""},
		{"END 下标元素后缀", condRule("EXECVE", "and", "END", "execve.proc.argv.2", "/8", ""), evNmap(), true, ""},
		{"REGEX 数组逐元素", condRule("EXECVE", "and", "REGEX", "execve.proc.argv", "-s[ST]", ""), evNmap(), true, "execve.proc.argv[1]=-sS"},
		{"REGEX 非字符串字段不命中", condRule("CONNECT", "and", "REGEX", "net.port", "^4", ""), evNet(443), false, ""},
		{"MT 命中", condRule("CONNECT", "and", "MT", "net.port", "1024", ""), evNet(4444), true, "net.port=4444"},
		{"MT 未中", condRule("CONNECT", "and", "MT", "net.port", "1024", ""), evNet(443), false, ""},
		{"LT 命中", condRule("CONNECT", "and", "LT", "net.port", "1024", ""), evNet(443), true, ""},
		{"LT 数值字符串(uint64 字段)", condRule("EXECVE", "and", "LT", "header.seq", "5", ""), evNmap(), true, ""},
		{"MT 字符串字段不命中", condRule("EXECVE", "and", "MT", "execve.proc.exe", "1", ""), evNmap(), false, ""},
		{"map 键路径", condRule("EXECVE", "and", "INCL", "execve.proc.envSel.LD_PRELOAD", "/tmp", ""), evNmap(), true, "execve.proc.envSel.LD_PRELOAD=/tmp/x.so"},
		{"缺数组下标", condRule("EXECVE", "and", "EQU", "execve.proc.argv.9", "nmap", ""), evNmap(), false, ""},
		{"穿标量路径不命中", condRule("EXECVE", "and", "EQU", "execve.proc.exe.0", "x", ""), evNmap(), false, ""},
		{"and 全中才中", andOK, evNmap(), true, "execve.proc.argv.0=nmap"},
		{"and 一条不中", andMiss, evNmap(), false, ""},
		{"or 任一中", orHit, evNmap(), true, "execve.proc.argv.0=nmap"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, desc := matchEvent(t, tc.rule, tc.ev)
			if hit != tc.hit {
				t.Fatalf("期望 hit=%v, 得到 %v (desc=%q)", tc.hit, hit, desc)
			}
			if tc.descHas != "" && !strings.Contains(desc, tc.descHas) {
				t.Fatalf("desc 期望包含 %q, 得到 %q", tc.descHas, desc)
			}
		})
	}
}

func TestEngineEndToEnd(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "r.yaml"), canonicalRule)
	s := &fakeSink{}
	e, err := New(dir, s, WithAlertRateLimit(1000, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	e.Handle(context.Background(), evNmap())
	e.Handle(context.Background(), evNet(443)) // CONNECT：无规则，静默
	waitUntil(t, 3*time.Second, func() bool { return len(s.snapshot()) == 1 }, "首条告警")

	a := s.snapshot()[0]
	if a.RuleID != "exec-recon-nmap" || a.Severity != "medium" || a.Mitre != "T1046" {
		t.Fatalf("告警元数据错误: %+v", a)
	}
	if a.TsMs != 1731400000123 || a.AgentID != "agent-1" || a.Hostname != "host-1" {
		t.Fatalf("事件头字段未透传: %+v", a)
	}
	if !strings.Contains(a.Summary, "exec-recon-nmap execve.proc.argv.0=nmap") {
		t.Fatalf("Summary 缺触发字段值: %q", a.Summary)
	}
	if !strings.Contains(a.EventRef, `"agentId":"agent-1"`) {
		t.Fatalf("EventRef 不是事件的 protojson: %q", a.EventRef[:min(120, len(a.EventRef))])
	}

	e.Handle(context.Background(), evNmapBigArgv(strings.Repeat("A", 6000)))
	waitUntil(t, 3*time.Second, func() bool { return len(s.snapshot()) == 2 }, "4KB 截断告警")
	if got := len(s.snapshot()[1].EventRef); got != 4096 {
		t.Fatalf("EventRef 应截 4096 字节, 得到 %d", got)
	}
}

func TestHotReload(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "nmap.yaml"), canonicalRule)
	s := &fakeSink{}
	e, err := New(dir, s, WithPollInterval(20*time.Millisecond), WithAlertRateLimit(1000, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if st := e.Stats(); st.RulesLoaded != 1 || st.RulesRejected != 0 {
		t.Fatalf("初始加载错误: %+v", st)
	}

	writeFile(t, filepath.Join(dir, "net.yaml"), netHighPortRule)
	waitUntil(t, 3*time.Second, func() bool {
		st := e.Stats()
		return st.Reloads == 1 && st.RulesLoaded == 2
	}, "新增规则热更生效")
	e.Handle(context.Background(), evNet(4444))
	waitUntil(t, 3*time.Second, func() bool {
		as := s.snapshot()
		return len(as) == 1 && as[0].RuleID == "net-high-port" && as[0].Severity == "high"
	}, "新规则产生告警")

	os.Remove(filepath.Join(dir, "nmap.yaml"))
	waitUntil(t, 3*time.Second, func() bool {
		st := e.Stats()
		return st.Reloads == 2 && st.RulesLoaded == 1
	}, "删除规则热更生效")
	e.Handle(context.Background(), evNmap())
	waitUntil(t, 3*time.Second, func() bool { return e.Stats().EventsProcessed >= 2 }, "事件处理完成")
	if n := len(s.snapshot()); n != 1 {
		t.Fatalf("已删规则不应再告警, 得到 %d 条", n)
	}

	writeFile(t, filepath.Join(dir, "bad.yaml"), "id: [broken\n")
	waitUntil(t, 3*time.Second, func() bool {
		st := e.Stats()
		return st.Reloads == 3 && st.RulesRejected == 1 && st.RulesLoaded == 1
	}, "坏规则跳过不废整批")
	before := len(s.snapshot())
	e.Handle(context.Background(), evNet(4444))
	waitUntil(t, 3*time.Second, func() bool {
		return len(s.snapshot()) == before+1 && e.Stats().AlertsEmitted == 2
	}, "好规则在坏规则混入后仍工作")
}

func TestRateLimit(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "r.yaml"), canonicalRule)
	s := &fakeSink{}
	e, err := New(dir, s, WithAlertRateLimit(3, time.Minute), WithPollInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for i := 0; i < 5; i++ {
		e.Handle(context.Background(), evNmap())
	}
	waitUntil(t, 3*time.Second, func() bool {
		st := e.Stats()
		return st.AlertsEmitted == 3 && st.AlertsLimited == 2
	}, "限速窗口 3 发 2 弃")
	if n := len(s.snapshot()); n != 3 {
		t.Fatalf("sink 应只收到 3 条, 得到 %d", n)
	}
}

func TestHandleNonBlocking(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "r.yaml"), canonicalRule)
	gate := make(chan struct{})
	s := &fakeSink{gate: gate}
	e, err := New(dir, s, WithQueueCap(8), WithAlertRateLimit(1000, time.Minute), WithPollInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	// 先占住两个 worker（sink 阻塞在 gate 上）
	e.Handle(context.Background(), evNmap())
	e.Handle(context.Background(), evNmap())
	waitUntil(t, 3*time.Second, func() bool { return int(s.calls.Load()) == 2 }, "worker 均阻塞在慢 sink")

	start := time.Now()
	for i := 0; i < 200; i++ {
		e.Handle(context.Background(), evNmap())
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Handle 被慢 sink 拖住: 200 次耗时 %v", elapsed)
	}
	st := e.Stats()
	if st.EventsDropped == 0 {
		t.Fatalf("队列(容量8)满应丢弃计数, got %+v", st)
	}

	close(gate)
	waitUntil(t, 3*time.Second, func() bool { return e.Stats().EventsProcessed >= 10 }, "排空积压")
}

func TestWorkerRecoversSinkPanic(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "r.yaml"), canonicalRule)
	s := &fakeSink{panicOnCall: 1}
	e, err := New(dir, s, WithAlertRateLimit(1000, time.Minute), WithPollInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for i := 0; i < 3; i++ {
		e.Handle(context.Background(), evNmap())
	}
	waitUntil(t, 3*time.Second, func() bool {
		st := e.Stats()
		return st.Panics >= 1 && len(s.snapshot()) == 2
	}, "panic 恢复且后续告警不受影响")
}

func TestHandleAfterClose(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "r.yaml"), canonicalRule)
	e, err := New(dir, &fakeSink{}, WithPollInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	before := e.Stats().EventsIn
	e.Handle(context.Background(), evNmap()) // 不得 panic
	if got := e.Stats().EventsIn; got != before {
		t.Fatalf("Close 后 Handle 应直接丢弃, EventsIn %d -> %d", before, got)
	}
}
