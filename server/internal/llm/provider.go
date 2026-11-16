// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Completion 是 provider 的单次产出。Verdict 已过 parseVerdict 校验；
// 解析两次均失败时返回 errParse（Verdict 零值），Raw 保留原文供落库审计。
type Completion struct {
	Verdict   Verdict
	TokensIn  int
	TokensOut int
	Raw       string
}

// errParse 标记「输出解析失败且重试已用尽」，调用方据此记 parse_error 不猜。
var errParse = fmt.Errorf("llm: completion failed schema validation after retry")

// Role 是多角色对抗链（Aida 模式）的角色标识，mock 按它返回对应形态输出，
// 真实 transport 不分支只透传。
type Role string

const (
	RoleInvestigator Role = "investigator" // 调查者：产假设
	RoleChallenger   Role = "challenger"   // 质疑者：逐假设裁决
	RoleJudge        Role = "judge"        // 裁决者：三态终判
)

// RoleCompletion 是一次角色调用的原始产出。transport 层不做 schema 解析——
// 各角色 JSON 的确定性校验在 adversarial 层（每个角色 schema 不同）。
type RoleCompletion struct {
	Raw       string
	TokensIn  int
	TokensOut int
}

// Provider 产单条研判。openai 兼容真实实现与 mock 判定表实现。
type Provider interface {
	Name() string
	Complete(ctx context.Context, system, user string) (Completion, error)
	// CompleteRole 是多角色路径的单次调用：同一 transport（温度 0 + JSON 强制），
	// 返回原文不判 verdict，schema 校验与重试语义由 adversarial 层持有。
	CompleteRole(ctx context.Context, role Role, system, user string) (RoleCompletion, error)
}

// NewProvider 按 cfg 构造。openai 且 API key 为空时强制 mock 并大声说
// （契约：无 key 也能全链路跑通）。
func NewProvider(cfg Config) Provider {
	if cfg.Provider == "openai" {
		if cfg.APIKey == "" {
			slog.Warn("XIEZHI_LLM_API_KEY empty with provider=openai, forcing mock provider")
			return NewMockProvider()
		}
		return NewOpenAIProvider(cfg.BaseURL, cfg.APIKey, cfg.Model)
	}
	return NewMockProvider()
}

// --- openai 兼容 chat/completions ---

type openaiProvider struct {
	baseURL string
	apiKey  string
	model   string
	client  *http.Client
}

func NewOpenAIProvider(baseURL, apiKey, model string) Provider {
	return &openaiProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		model:   model,
		client:  &http.Client{Timeout: 60 * time.Second},
	}
}

func (p *openaiProvider) Name() string { return p.model }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model          string        `json:"model"`
	Messages       []chatMessage `json:"messages"`
	Temperature    float64       `json:"temperature"`
	ResponseFormat *struct {
		Type string `json:"type"`
	} `json:"response_format,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// Complete 调 chat/completions（temperature 0 + response_format json_object）。
// 输出解析失败原样重试 1 次（A2 容错双通道的收敛版），再失败返回 errParse。
func (p *openaiProvider) Complete(ctx context.Context, system, user string) (Completion, error) {
	var lastRaw string
	for attempt := 0; attempt < 2; attempt++ {
		raw, tin, tout, err := p.call(ctx, system, user)
		if err != nil {
			return Completion{}, err
		}
		lastRaw = raw
		if v, perr := parseVerdict(raw); perr == nil {
			return Completion{Verdict: v, TokensIn: tin, TokensOut: tout, Raw: raw}, nil
		} else if attempt == 0 {
			slog.Warn("llm verdict parse failed, retrying once", "err", perr)
		}
	}
	return Completion{Raw: lastRaw}, errParse
}

// CompleteRole 单次调用返回原文：角色 schema 校验与「重试一次」语义在
// adversarial 层（provider 不该知道各角色的 JSON 形态）。
func (p *openaiProvider) CompleteRole(ctx context.Context, _ Role, system, user string) (RoleCompletion, error) {
	raw, tin, tout, err := p.call(ctx, system, user)
	if err != nil {
		return RoleCompletion{}, err
	}
	return RoleCompletion{Raw: raw, TokensIn: tin, TokensOut: tout}, nil
}

func (p *openaiProvider) call(ctx context.Context, system, user string) (content string, tokensIn, tokensOut int, err error) {
	reqBody := chatRequest{
		Model: p.model,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Temperature: 0,
		ResponseFormat: &struct {
			Type string `json:"type"`
		}{Type: "json_object"},
	}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return "", 0, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return "", 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	resp, err := p.client.Do(req)
	if err != nil {
		return "", 0, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", 0, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, 0, fmt.Errorf("llm: chat/completions %s: %s", resp.Status, truncateForLog(body))
	}
	var cr chatResponse
	if err := json.Unmarshal(body, &cr); err != nil {
		return "", 0, 0, fmt.Errorf("llm: decode response: %w", err)
	}
	if len(cr.Choices) == 0 {
		return "", 0, 0, fmt.Errorf("llm: empty choices")
	}
	return cr.Choices[0].Message.Content, cr.Usage.PromptTokens, cr.Usage.CompletionTokens, nil
}

func truncateForLog(b []byte) string {
	s := string(b)
	if len(s) > 512 {
		s = s[:512] + "..."
	}
	return s
}

// --- mock：确定性判定表（e2e 与测试用，不调真实 LLM） ---

type mockProvider struct{}

func NewMockProvider() Provider { return mockProvider{} }

func (mockProvider) Name() string { return "mock" }

// mockVerdict 是按 RuleID 的确定性判定表（契约给定）：firstseen/* 记良性
// 候选（info 级基线噪声画像），两条高危 exec 规则记 escalate，其余记证据
// 不足。置信度与文案固定，端到端断言可直接依赖。
func mockVerdict(ruleID string) Verdict {
	switch {
	case strings.HasPrefix(ruleID, "firstseen/"):
		return Verdict{
			State:      StateBenignCand,
			Confidence: 0.9,
			Reasoning:  "first-seen 基线学习告警，mock 判定为良性候选：" + ruleID,
			Tactic:     "",
		}
	case ruleID == "exec-curl-pipe-shell" || ruleID == "exec-miner-config":
		return Verdict{
			State:      StateEscalate,
			Confidence: 0.95,
			Reasoning:  "命中高危执行链规则 " + ruleID + "，mock 判定升级处置",
			Tactic:     "T1059",
		}
	default:
		return Verdict{
			State:      StateInsufficient,
			Confidence: 0.5,
			Reasoning:  "规则 " + ruleID + " 无匹配判定表项，mock 判定证据不足",
			Tactic:     "",
		}
	}
}

func (m mockProvider) Complete(_ context.Context, system, user string) (Completion, error) {
	// 规则 ID 从 user 消息的证据 JSON 里取：mock 也走打包产物，保证 e2e 路径
	// 与真实 provider 完全一致（同一份证据，只是判定来源不同）。
	ruleID := ruleIDFromUserPrompt(user)
	v := mockVerdict(ruleID)
	return Completion{
		Verdict:   v,
		TokensIn:  (len(system) + len(user)) / 4,
		TokensOut: 64,
		Raw:       mustJSON(v),
	}, nil
}

// CompleteRole 按角色返回对应形态的确定性输出：判定语义（rule_id → 三态）
// 与单角色判定表一致且只在 judge 段生效，investigator/challenger 段出与
// rule_id 相关的固定文本，三段拼起来可端到端断言。
func (m mockProvider) CompleteRole(_ context.Context, role Role, system, user string) (RoleCompletion, error) {
	ruleID := ruleIDFromUserPrompt(user)
	var raw string
	switch role {
	case RoleInvestigator:
		raw = mustJSON(struct {
			Hypotheses []Hypothesis `json:"hypotheses"`
		}{Hypotheses: []Hypothesis{
			{Claim: Untrusted("规则 " + ruleID + " 命中真实攻击行为"), EvidenceNeeded: Untrusted("触发进程的完整命令行与父进程链"), SeverityHint: "high"},
			{Claim: Untrusted("规则 " + ruleID + " 由例行运维或软件更新触发"), EvidenceNeeded: Untrusted("主机资产标签与变更窗口记录"), SeverityHint: "low"},
			{Claim: Untrusted("规则 " + ruleID + " 的事件由攻击者伪造"), EvidenceNeeded: Untrusted("同主机相邻事件的关联记录"), SeverityHint: "medium"},
		}})
	case RoleChallenger:
		raw = mustJSON(struct {
			Challenges []Challenge `json:"challenges"`
		}{Challenges: []Challenge{
			{HypothesisIdx: 0, Verdict: "supports", Reasoning: Untrusted("mock 质疑者：规则 " + ruleID + " 触发事件与攻击假设一致")},
			{HypothesisIdx: 1, Verdict: "insufficient", Reasoning: Untrusted("mock 质疑者：规则 " + ruleID + " 无资产标签，良性场景无法确认"), MissingEvidence: Untrusted("主机资产标签")},
			{HypothesisIdx: 2, Verdict: "insufficient", Reasoning: Untrusted("mock 质疑者：规则 " + ruleID + " 无法排除伪造，需相邻事件关联"), MissingEvidence: Untrusted("相邻事件关联")},
		}})
	case RoleJudge:
		raw = mustJSON(judgeVerdict{
			Verdict:           mockVerdict(ruleID),
			HypothesesSummary: "mock 裁决者：规则 " + ruleID + " 三假设中攻击假设获支持，按判定表裁决",
		})
	default:
		return RoleCompletion{}, fmt.Errorf("llm: mock CompleteRole unknown role %q", role)
	}
	return RoleCompletion{
		Raw:       raw,
		TokensIn:  (len(system) + len(user)) / 4,
		TokensOut: 64,
	}, nil
}

// ruleIDFromUserPrompt 证据 JSON 形如 {"alert":{...,"rule_id":"x",...}}。
// 多角色 user 消息里证据 JSON 之后还拼着假设/质疑段，Decoder 只读第一个
// JSON 值即可，不因尾随文本解析失败。
func ruleIDFromUserPrompt(user string) string {
	i := strings.Index(user, "{")
	if i < 0 {
		return ""
	}
	var ev struct {
		Alert struct {
			RuleID string `json:"rule_id"`
		} `json:"alert"`
	}
	if err := json.NewDecoder(strings.NewReader(user[i:])).Decode(&ev); err != nil {
		return ""
	}
	return ev.Alert.RuleID
}

func mustJSON[T any](v T) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
