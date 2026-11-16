// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// runMultiRole 直接对 mock 三步全链路断言：判定语义走单角色判定表，token
// 是三次调用之和，summary 带回 rule_id。
func TestRunMultiRoleMockChain(t *testing.T) {
	ev, err := BuildEvidence(context.Background(), testAlert(), 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ev.MarshalBudgeted()
	if err != nil {
		t.Fatal(err)
	}
	res, err := runMultiRole(context.Background(), NewMockProvider(), b)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict.State != StateEscalate || res.Verdict.Confidence != 0.95 || res.Verdict.Tactic != "T1059" {
		t.Errorf("judge verdict mismatch: %+v", res.Verdict)
	}
	if !strings.Contains(res.Summary, "exec-curl-pipe-shell") {
		t.Errorf("summary should carry rule id: %q", res.Summary)
	}
	if res.TokensIn <= 0 || res.TokensOut != 3*64 {
		t.Errorf("tokens = %d/%d, want positive in and 3x64 out", res.TokensIn, res.TokensOut)
	}
}

// mock 判定表语义在 multi 路径保持不变：三类规则各落一行，reasoning 带
// [multi] 前缀与 hypotheses 摘要，tokens 为三段之和。
func TestHandleAlertMultiRoleEndToEnd(t *testing.T) {
	cases := []struct {
		ruleID string
		want   State
		conf   float64
	}{
		{"exec-curl-pipe-shell", StateEscalate, 0.95},
		{"firstseen/exe", StateBenignCand, 0.9},
		{"net-mining-pool", StateInsufficient, 0.5},
	}
	for _, c := range cases {
		store := &fakeStore{}
		cfg := testConfig()
		cfg.MultiRole = true
		w := NewWorker(cfg, NewMockProvider(), store, nil, nil)

		a := testAlert()
		a.RuleID = c.ruleID
		w.HandleAlert(context.Background(), a)

		if got := store.len(); got != 1 {
			t.Fatalf("%s: store rows = %d, want 1", c.ruleID, got)
		}
		row := store.last()
		if row.State != c.want || row.Confidence != c.conf {
			t.Errorf("%s: verdict = %s/%v, want %s/%v", c.ruleID, row.State, row.Confidence, c.want, c.conf)
		}
		if !strings.HasPrefix(row.Reasoning, "[multi] ") {
			t.Errorf("%s: reasoning missing [multi] prefix: %q", c.ruleID, row.Reasoning)
		}
		if !strings.Contains(row.Reasoning, "hypotheses: ") {
			t.Errorf("%s: reasoning missing hypotheses summary: %q", c.ruleID, row.Reasoning)
		}
		if row.TokensOut != 3*64 {
			t.Errorf("%s: tokens_out = %d, want 3 mock calls", c.ruleID, row.TokensOut)
		}
		if w.Stats()["triaged"] != 1 {
			t.Errorf("%s: stats = %+v", c.ruleID, w.Stats())
		}
	}
}

// 角色链失败（schema 不合或 transport 错）必须降级单角色 loudly：row 带
// [single_fallback] 前缀且 verdict 来自单角色路径。
func TestHandleAlertMultiRoleFallback(t *testing.T) {
	for name, p := range map[string]*trackingProvider{
		"schema-mismatch": {verdict: mockVerdict("net-mining-pool")},
		"transport-error": {verdict: mockVerdict("net-mining-pool"), roleErr: errors.New("role call down")},
	} {
		store := &fakeStore{}
		cfg := testConfig()
		cfg.MultiRole = true
		w := NewWorker(cfg, p, store, nil, nil)
		w.HandleAlert(context.Background(), testAlert())

		if got := store.len(); got != 1 {
			t.Fatalf("%s: fallback must persist a row, got %d", name, got)
		}
		row := store.last()
		if !strings.HasPrefix(row.Reasoning, "[single_fallback] ") {
			t.Errorf("%s: reasoning = %q, want [single_fallback] prefix", name, row.Reasoning)
		}
		if row.State != StateInsufficient {
			t.Errorf("%s: state = %s, want single-path verdict", name, row.State)
		}
		if row.TokensOut != 5 { // trackingProvider 单次 TokensOut=5，仅一次 Complete
			t.Errorf("%s: tokens_out = %d, want single fallback call", name, row.TokensOut)
		}
		if w.Stats()["triaged"] != 1 || w.Stats()["parse_error"] != 0 {
			t.Errorf("%s: stats = %+v", name, w.Stats())
		}
	}
}

// 外层预算耗尽（父 ctx 到期）时多角色失败不降级：计 timeout、不落行——
// 降级也要花预算，没预算就不猜。
func TestHandleAlertMultiRoleTimeout(t *testing.T) {
	p := &trackingProvider{delay: 200 * time.Millisecond}
	store := &fakeStore{}
	cfg := testConfig()
	cfg.MultiRole = true
	w := NewWorker(cfg, p, store, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	w.HandleAlert(ctx, testAlert())

	if store.len() != 0 {
		t.Error("timed-out multi-role triage must not persist")
	}
	if w.Stats()["timeout"] != 1 {
		t.Errorf("timeout = %d, want 1", w.Stats()["timeout"])
	}
}

func TestParseHypotheses(t *testing.T) {
	ok, err := parseHypotheses(`{"hypotheses":[{"claim":"curl 管道进 shell","evidence_needed":"进程树","severity_hint":"high"}]}`)
	if err != nil {
		t.Fatalf("bare form must parse: %v", err)
	}
	if ok[0].Claim != "curl 管道进 shell" || ok[0].SeverityHint != "high" {
		t.Errorf("hypothesis = %+v", ok[0])
	}

	wrapped, err := parseHypotheses(`{"hypotheses":[{"claim":{"untrusted":"回显攻击文本"},"evidence_needed":"e","severity_hint":"low"}]}`)
	if err != nil {
		t.Fatalf("wrapped form must parse: %v", err)
	}
	if wrapped[0].Claim != "回显攻击文本" {
		t.Errorf("wrapped claim = %q", wrapped[0].Claim)
	}

	fenced, err := parseHypotheses("```json\n" + `{"hypotheses":[{"claim":"c","evidence_needed":"e","severity_hint":""}]}` + "\n```")
	if err != nil || len(fenced) != 1 {
		t.Errorf("fenced form: %v %+v", err, fenced)
	}

	many, err := parseHypotheses(`{"hypotheses":[` + strings.Repeat(`{"claim":"c","evidence_needed":"e","severity_hint":"low"},`, 9) + `{"claim":"c","evidence_needed":"e","severity_hint":"low"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(many) != maxRoleOutput {
		t.Errorf("hypotheses = %d, want capped at %d", len(many), maxRoleOutput)
	}

	for name, content := range map[string]string{
		"empty":     ``,
		"not-json":  `hypotheses!`,
		"no-list":   `{"hypotheses":[]}`,
		"no-claims": `{"hypotheses":[{"claim":"","evidence_needed":"e","severity_hint":"high"}]}`,
		"verdict":   `{"state":"escalate","confidence":1,"reasoning":"r","tactic":""}`,
	} {
		if _, err := parseHypotheses(content); err == nil {
			t.Errorf("%s: expected error, got none", name)
		}
	}
}

func TestParseChallenges(t *testing.T) {
	ok, err := parseChallenges(`{"challenges":[{"hypothesis_idx":0,"verdict":"supports","reasoning":"r","missing_evidence":""},{"hypothesis_idx":1,"verdict":"refutes","reasoning":{"untrusted":"r2"},"missing_evidence":""}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(ok) != 2 || ok[1].Reasoning != "r2" {
		t.Errorf("challenges = %+v", ok)
	}

	capped, err := parseChallenges(`{"challenges":[` + strings.Repeat(`{"hypothesis_idx":0,"verdict":"insufficient","reasoning":"r","missing_evidence":"m"},`, 9) + `{"hypothesis_idx":0,"verdict":"insufficient","reasoning":"r","missing_evidence":"m"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(capped) != maxRoleOutput {
		t.Errorf("challenges = %d, want capped at %d", len(capped), maxRoleOutput)
	}

	for name, content := range map[string]string{
		"empty":       ``,
		"no-list":     `{"challenges":[]}`,
		"bad-verdict": `{"challenges":[{"hypothesis_idx":0,"verdict":"supported","reasoning":"r","missing_evidence":""}]}`,
	} {
		if _, err := parseChallenges(content); err == nil {
			t.Errorf("%s: expected error, got none", name)
		}
	}
}

func TestParseJudgeVerdict(t *testing.T) {
	ok, err := parseJudgeVerdict(`{"state":"escalate","confidence":0.9,"reasoning":"r","tactic":"T1059","hypotheses_summary":"攻击假设获支持"}`)
	if err != nil {
		t.Fatal(err)
	}
	if ok.State != StateEscalate || ok.HypothesesSummary != "攻击假设获支持" {
		t.Errorf("judge verdict = %+v", ok)
	}

	// hypotheses_summary 缺省可接受：单角色形态的 verdict 仍是合法裁决输出。
	noSummary, err := parseJudgeVerdict(`{"state":"benign_candidate","confidence":2,"reasoning":"r","tactic":""}`)
	if err != nil {
		t.Fatal(err)
	}
	if noSummary.Confidence != 1 || noSummary.HypothesesSummary != "" {
		t.Errorf("clamp/summary default broken: %+v", noSummary)
	}

	for name, content := range map[string]string{
		"empty":     ``,
		"bad-state": `{"state":"close_alert","confidence":0.9,"reasoning":"r","tactic":"","hypotheses_summary":""}`,
		"not-json":  `judge says escalate`,
	} {
		if _, err := parseJudgeVerdict(content); err == nil {
			t.Errorf("%s: expected error, got none", name)
		}
	}
}

// 角色间投喂的假设/质疑文本必须以 untrusted 包裹进入下一角色上下文。
func TestRoleOutputsWrappedDownstream(t *testing.T) {
	hypJSON, err := json.Marshal(struct {
		Hypotheses []Hypothesis `json:"hypotheses"`
	}{Hypotheses: []Hypothesis{{Claim: Untrusted("curl | sh"), EvidenceNeeded: Untrusted("树"), SeverityHint: "high"}}})
	if err != nil {
		t.Fatal(err)
	}
	u := challengerUser([]byte(`{"alert":{"rule_id":"r"}}`), hypJSON)
	if !strings.Contains(u, `{"claim":{"untrusted":"curl | sh"}`) {
		t.Errorf("claim not wrapped when fed downstream: %s", u)
	}
}

func TestConfigMultiRoleEnv(t *testing.T) {
	t.Setenv("XIEZHI_LLM_MULTI_ROLE", "true")
	cfg, err := ConfigFromEnv()
	if err != nil || !cfg.MultiRole {
		t.Errorf("true: cfg=%v err=%v", cfg.MultiRole, err)
	}
	t.Setenv("XIEZHI_LLM_MULTI_ROLE", "false")
	cfg, err = ConfigFromEnv()
	if err != nil || cfg.MultiRole {
		t.Errorf("false: cfg=%v err=%v", cfg.MultiRole, err)
	}
	t.Setenv("XIEZHI_LLM_MULTI_ROLE", "yes")
	if _, err = ConfigFromEnv(); err == nil {
		t.Error("garbage value must fail startup")
	}
}
