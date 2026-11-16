// SPDX-License-Identifier: Apache-2.0

package firstseen

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestParseExePrefixes(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{",,", nil},
		{"/usr", []string{"/usr"}},
		{" /usr, /tmp ,,/var ", []string{"/usr", "/tmp", "/var"}},
	}
	for _, c := range cases {
		got := ParseExePrefixes(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("ParseExePrefixes(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("ParseExePrefixes(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestKeyKindAndExePath(t *testing.T) {
	exeKey := encodeKey(KindExe, "h1", "/tmp/x")
	if k := KeyKind(exeKey); k != KindExe {
		t.Fatalf("KeyKind = %q, want %q", k, KindExe)
	}
	if exe, ok := KeyExePath(exeKey); !ok || exe != "/tmp/x" {
		t.Fatalf("KeyExePath = %q,%v", exe, ok)
	}
	connKey := encodeKey(KindConnTarget, "h1", "1.2.3.4:80")
	if k := KeyKind(connKey); k != KindConnTarget {
		t.Fatalf("KeyKind = %q, want %q", k, KindConnTarget)
	}
	if _, ok := KeyExePath(connKey); ok {
		t.Fatal("non-exe key must not decode an exe path")
	}
	parentKey := encodeKey(KindExeParent, "h1", "/tmp/x", "/bin/bash")
	if _, ok := KeyExePath(parentKey); ok {
		t.Fatal("exe_parent key must not decode via KeyExePath")
	}
}

func obsAt(kind, host, exe string, tsMs int64) Obs {
	return Obs{Key: encodeKey(kind, host, exe), Kind: kind, Host: host, AgentID: "ag-" + host, TsMs: tsMs, Count: 1}
}

const hourMs = int64(time.Hour / time.Millisecond)

// 白名单命中：exe 键完全压告警，digest 窗口里也不出现（摘要语义=白名单外）。
func TestDigestWhitelistSuppresses(t *testing.T) {
	sink := &fakeSink{}
	d := newDigest([]string{"/usr", "/opt"}, sink)
	d.add(obsAt(KindExe, "h1", "/usr/bin/curl", hourMs+1000))
	d.add(obsAt(KindExe, "h1", "/opt/go/bin/x", hourMs+2000))
	d.add(obsAt(KindExe, "h1", "/usrshare/fake", hourMs+3000)) // 字符串前缀即命中（/usr 是 /usrshare 的前缀），保持最简语义
	d.flushAll(time.UnixMilli(hourMs + 2*hourMs))
	if alerts := sink.snapshot(); len(alerts) != 0 {
		t.Fatalf("whitelisted exe produced alerts: %+v", alerts)
	}
}

func TestDigestAggregatesByHourWindow(t *testing.T) {
	sink := &fakeSink{}
	d := newDigest(nil, sink) // 空白名单：全部入窗
	h9, h10 := 9*hourMs, 10*hourMs
	d.add(obsAt(KindExe, "h1", "/tmp/a", h10+100))
	d.add(obsAt(KindExe, "h1", "/tmp/b", h10+200))
	d.add(obsAt(KindExe, "h2", "/tmp/c", h10+300))
	d.add(obsAt(KindConnTarget, "h1", "1.2.3.4:80", h10+400))
	d.add(obsAt(KindExe, "h1", "/tmp/d", h9+100)) // 早一小时，独立窗口

	// 10:30：h9 小时已结束（终点 10:00）先发；h10 小时未结束不发
	d.flush(time.UnixMilli(h10 + 30*60*1000))
	if got := len(sink.snapshot()); got != 1 {
		t.Fatalf("mid-hour flush = %d alerts, want 1 (closed h9 window only)", got)
	}

	// 11:00 过后：h10 的三个窗口补发，共 4 条 digest，按小时/主机/kind 排序
	d.flush(time.UnixMilli(h10 + hourMs + 1))
	alerts := sink.snapshot()
	if len(alerts) != 4 {
		t.Fatalf("alerts = %d, want 4: %+v", len(alerts), alerts)
	}
	want := []struct {
		ruleID, summary string
	}{
		{"firstseen/exe/digest", "host h1 kind exe 首见 1 条（白名单外）"}, // h9 窗口最先
		// h10 窗口按 host 再 kind 排序：conn_target 字典序在 exe 前
		{"firstseen/conn_target/digest", "host h1 kind conn_target 首见 1 条（白名单外）"},
		{"firstseen/exe/digest", "host h1 kind exe 首见 2 条（白名单外）"},
		{"firstseen/exe/digest", "host h2 kind exe 首见 1 条（白名单外）"},
	}
	for i, w := range want {
		a := alerts[i]
		if a.RuleID != w.ruleID || a.Summary != w.summary || a.Severity != "info" {
			t.Errorf("alert[%d] = %s | %s, want %s | %s", i, a.RuleID, a.Summary, w.ruleID, w.summary)
		}
		if a.Hostname == "" || a.AgentID == "" {
			t.Errorf("alert[%d] missing host/agent: %+v", i, a)
		}
	}

	// 已 flush 的窗口不重发
	d.flush(time.UnixMilli(h10 + 2*hourMs))
	if got := len(sink.snapshot()); got != 4 {
		t.Fatalf("re-flush duplicated alerts: %d", got)
	}
}

// handler 全链：新 exe 键写 store（PG 行照写语义）、Close 时未满小时窗口也
// 发 digest；重复键被 LRU 吸收只算一次首见。
func TestHandlerDigestEndToEnd(t *testing.T) {
	st := newFakeStore()
	sink := &fakeSink{}
	h := New(st, sink, Config{BatchKeys: 10, BatchEvery: time.Hour})
	h.Handle(context.Background(), evExecve(uint64(hourMs+1234), "/tmp/curl"))
	h.Handle(context.Background(), evExecve(uint64(hourMs+2345), "/tmp/curl")) // LRU 命中
	h.Close()

	if st.calls() != 1 || len(st.batches[0]) != 1 {
		t.Fatalf("upsert calls = %d, want 1 (LRU must absorb the repeat)", st.calls())
	}
	alerts := sink.snapshot()
	if len(alerts) != 1 {
		t.Fatalf("digest alerts = %d, want 1: %+v", len(alerts), alerts)
	}
	a := alerts[0]
	if a.RuleID != "firstseen/exe/digest" || a.Hostname != "h1" || a.AgentID != "ag1" || a.Severity != "info" {
		t.Fatalf("digest alert = %+v", a)
	}
	if !strings.Contains(a.Summary, "kind exe 首见 1 条（白名单外）") {
		t.Fatalf("summary = %q", a.Summary)
	}
}

// 白名单经 env 注入的全链验证：/usr 下首见仍写库但零告警。
func TestHandlerWhitelistFromEnv(t *testing.T) {
	t.Setenv(envExePrefixes, "/usr")
	st := newFakeStore()
	sink := &fakeSink{}
	h := New(st, sink, Config{BatchKeys: 10, BatchEvery: time.Hour})
	h.Handle(context.Background(), evExecve(1234, "/usr/bin/curl"))
	h.Close()

	if st.calls() != 1 || len(st.batches[0]) != 1 {
		t.Fatalf("whitelisted key must still be recorded, calls = %d", st.calls())
	}
	if alerts := sink.snapshot(); len(alerts) != 0 {
		t.Fatalf("whitelisted key alerted: %+v", alerts)
	}
}
