// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"os"
	"testing"
)

func TestMockVerdictTable(t *testing.T) {
	cases := []struct {
		ruleID string
		want   Verdict
	}{
		{"firstseen/exe", Verdict{StateBenignCand, 0.9, "first-seen 基线学习告警，mock 判定为良性候选：firstseen/exe", ""}},
		{"firstseen/parent_exe", Verdict{StateBenignCand, 0.9, "first-seen 基线学习告警，mock 判定为良性候选：firstseen/parent_exe", ""}},
		{"exec-curl-pipe-shell", Verdict{StateEscalate, 0.95, "命中高危执行链规则 exec-curl-pipe-shell，mock 判定升级处置", "T1059"}},
		{"exec-miner-config", Verdict{StateEscalate, 0.95, "命中高危执行链规则 exec-miner-config，mock 判定升级处置", "T1059"}},
		{"net-mining-pool", Verdict{StateInsufficient, 0.5, "规则 net-mining-pool 无匹配判定表项，mock 判定证据不足", ""}},
	}
	for _, c := range cases {
		if got := mockVerdict(c.ruleID); got != c.want {
			t.Errorf("mockVerdict(%q) = %+v want %+v", c.ruleID, got, c.want)
		}
	}
}

// mock provider 必须从打包产物取 rule_id（与真实 provider 同路径），
// 保证 e2e 断言的是完整链路而非旁路。
func TestMockCompleteUsesEvidenceRuleID(t *testing.T) {
	ev, err := BuildEvidence(context.Background(), testAlert(), 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ev.MarshalBudgeted()
	if err != nil {
		t.Fatal(err)
	}
	comp, err := NewMockProvider().Complete(context.Background(), systemPrompt, userPrompt(b))
	if err != nil {
		t.Fatal(err)
	}
	// testAlert 的 rule_id 是 exec-curl-pipe-shell → 判定表 escalate 0.95。
	if comp.Verdict.State != StateEscalate || comp.Verdict.Confidence != 0.95 {
		t.Errorf("unexpected verdict %+v", comp.Verdict)
	}
	if comp.TokensIn <= 0 {
		t.Errorf("mock tokens_in should be a positive estimate, got %d", comp.TokensIn)
	}
	if NewMockProvider().Name() != "mock" {
		t.Error("mock provider name")
	}
}

func TestProviderSelection(t *testing.T) {
	// openai + key → openaiProvider。
	p := NewProvider(Config{Provider: "openai", APIKey: "k", BaseURL: "http://x", Model: "m"})
	if _, ok := p.(*openaiProvider); !ok {
		t.Errorf("openai with key must build openaiProvider, got %T", p)
	}
	// openai 无 key → 强制 mock（无 key 也能全链路跑通）。
	p = NewProvider(Config{Provider: "openai"})
	if _, ok := p.(mockProvider); !ok {
		t.Errorf("openai without key must fall back to mock, got %T", p)
	}
	// 未知 provider 也落 mock（ConfigFromEnv 已挡非法值，这里兜底）。
	p = NewProvider(Config{Provider: "weird"})
	if _, ok := p.(mockProvider); !ok {
		t.Errorf("unknown provider must fall back to mock, got %T", p)
	}
}

// 活端点冒烟（默认关）：XIEZHI_LLM_LIVE=1 且带 XIEZHI_LLM_API_KEY 时对真实
// provider 跑一轮 Complete，实证 parseVerdict 全链（推理模型的 content 解析、
// json_object 响应格式、token 计数）。key 只从 env 读，绝不入仓。
func TestLiveProviderComplete(t *testing.T) {
	if os.Getenv("XIEZHI_LLM_LIVE") != "1" || os.Getenv("XIEZHI_LLM_API_KEY") == "" {
		t.Skip("live: set XIEZHI_LLM_LIVE=1 XIEZHI_LLM_API_KEY=... (BASE_URL/MODEL 可选，默认 DeepSeek)")
	}
	base, model := os.Getenv("XIEZHI_LLM_BASE_URL"), os.Getenv("XIEZHI_LLM_MODEL")
	if base == "" {
		base = "https://api.deepseek.com"
	}
	if model == "" {
		model = "deepseek-flash"
	}
	ev, err := BuildEvidence(context.Background(), testAlert(), 0, nil, nil)
	if err != nil {
		t.Fatalf("BuildEvidence: %v", err)
	}
	evJSON, err := ev.MarshalBudgeted()
	if err != nil {
		t.Fatalf("MarshalBudgeted: %v", err)
	}
	p := NewOpenAIProvider(base, os.Getenv("XIEZHI_LLM_API_KEY"), model)
	c, err := p.Complete(context.Background(), systemPrompt, userPrompt(evJSON))
	if err != nil {
		t.Fatalf("Complete against live provider: %v", err)
	}
	if c.TokensIn == 0 || c.TokensOut == 0 {
		t.Errorf("token accounting zero: in=%d out=%d", c.TokensIn, c.TokensOut)
	}
	t.Logf("verdict=%+v raw=%s", c.Verdict, c.Raw)
}
