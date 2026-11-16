// SPDX-License-Identifier: Apache-2.0

// Package llm 是 M4 的 shadow 研判：
// 消费 NATS xiezhi.alerts 的告警副本，打包证据调 LLM 产三态结论，写 ClickHouse
// llm_triage。全程 shadow——不回馈告警流、benign_candidate 零关闭权（只产
// 候选记录，删/闭告警永远走人工）。单角色失败画像（漏报 40-70%、空检索错关
// 98.6%）靠架构缓解：三态输出 + 零关闭权 + shadow，不靠 prompt；XIEZHI_LLM_
// MULTI_ROLE=true 时走 adversarial.go 的三角色对抗链（Aida 模式），失败降级
// 单角色。
package llm

import (
	"context"
	"os"
	"strconv"
	"time"
)

// State 是研判三态。parse_error 不是第四态研判结果，是解析两次均失败后的
// 显式记错落库（「不猜」），供事后审计与 prompt 迭代。
type State string

const (
	StateEscalate     State = "escalate"              // 高概率真实攻击，需人工升级
	StateInsufficient State = "insufficient_evidence" // 证据不足以判定
	StateBenignCand   State = "benign_candidate"      // 良性候选，绝不据此关闭告警
	StateParseError   State = "parse_error"           // 输出 JSON 两次解析失败
)

// validState 白名单（LLM 输出边界校验；parse_error 只由内部路径写入）。
var validStates = map[State]bool{
	StateEscalate:     true,
	StateInsufficient: true,
	StateBenignCand:   true,
}

// Verdict 是 LLM 的输出契约（严格 JSON，温度 0）。
type Verdict struct {
	State      State   `json:"state"`
	Confidence float64 `json:"confidence"`
	Reasoning  string  `json:"reasoning"`
	Tactic     string  `json:"tactic"` // ATT&CK 技术编号，如 T1059；未知留空
}

// TriageRow 是 llm_triage 的行投影。
type TriageRow struct {
	TsMs       int64 // 研判完成时刻
	AlertTsMs  int64
	AgentID    string
	RuleID     string
	State      State
	Confidence float64
	Reasoning  string
	Tactic     string
	Model      string
	LatencyMs  int64
	TokensIn   int
	TokensOut  int
}

// TriageStore 写入侧（CH 适配器与测试 fake 实现）。
type TriageStore interface {
	SaveTriage(ctx context.Context, row TriageRow) error
}

// TriageQuery 是 /triage 查询过滤。
type TriageQuery struct {
	Limit  int
	State  string
	RuleID string
}

// TriageReader 查询侧（TriageHandler 用）。
type TriageReader interface {
	RecentTriages(ctx context.Context, q TriageQuery) ([]map[string]any, error)
}

// EventSummary 是历史事件的打包输入（ts/event_type 可信，Body 是攻击者
// 可控的事件原文，打包时截断并包 untrusted）。
type EventSummary struct {
	TsMs int64
	Type string
	Body string
}

// EventFetcher 按 agent+时间窗取最近事件。store.CHStore 的 Querier 无时间窗
// 参数，main 装配时以闭包适配（RecentEvents 倒序取回后过滤 sinceMs）。
type EventFetcher interface {
	RecentByAgent(ctx context.Context, agentID string, sinceMs int64, limit int) ([]EventSummary, error)
}

// SubtreeSource 是进程树证据源；*session.Handler 直接满足（duck-typed，
// 避免 llm 反向依赖 session 包）。
type SubtreeSource interface {
	SubtreeJSON(host string, pid int32, depth int) (string, error)
}

// Config 全部来自 env（边界解析，内部只信任已归一的值）。
type Config struct {
	Provider       string // openai|mock
	BaseURL        string
	APIKey         string
	Model          string
	MaxConcurrency int
	TriageSinceMin int           // 只研判最近 N 分钟的告警
	Timeout        time.Duration // 单条研判全链路超时（multi 模式下抬到 multiRoleTimeout）
	MultiRole      bool          // 多角色对抗链（Aida 模式），灰度开关，默认 false
}

// ConfigFromEnv 读取契约 env。非法值一律 fail（返回 error 由调用方决定拒启），
// 唯一软降级是 provider=openai 且 API key 为空 → NewProvider 强制 mock 并 Warn。
// Triage_Since_Min 同时接受全大写变体（Linux env 惯例），契约原名为
// XIEZHI_LLM_Triage_Since_Min。
func ConfigFromEnv() (Config, error) {
	cfg := Config{
		Provider:       envOr("XIEZHI_LLM_PROVIDER", "mock"),
		BaseURL:        envOr("XIEZHI_LLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4"),
		APIKey:         os.Getenv("XIEZHI_LLM_API_KEY"),
		Model:          envOr("XIEZHI_LLM_MODEL", "glm-4.7-flash"),
		MaxConcurrency: 2,
		TriageSinceMin: 15,
		Timeout:        30 * time.Second,
	}
	if v, err := posIntEnv("XIEZHI_LLM_MAX_CONCURRENCY", cfg.MaxConcurrency); err != nil {
		return Config{}, err
	} else {
		cfg.MaxConcurrency = v
	}
	since := 15
	if v := os.Getenv("XIEZHI_LLM_TRIAGE_SINCE_MIN"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return Config{}, errEnv("XIEZHI_LLM_TRIAGE_SINCE_MIN", v)
		}
		since = n
	} else if v := os.Getenv("XIEZHI_LLM_Triage_Since_Min"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return Config{}, errEnv("XIEZHI_LLM_Triage_Since_Min", v)
		}
		since = n
	}
	cfg.TriageSinceMin = since
	if cfg.Provider != "openai" && cfg.Provider != "mock" {
		return Config{}, errEnv("XIEZHI_LLM_PROVIDER", cfg.Provider)
	}
	if v := os.Getenv("XIEZHI_LLM_MULTI_ROLE"); v != "" {
		if v != "true" && v != "false" {
			return Config{}, errEnv("XIEZHI_LLM_MULTI_ROLE", v)
		}
		cfg.MultiRole = v == "true"
	}
	return cfg, nil
}

type envError struct{ key, val string }

func (e *envError) Error() string {
	return e.key + " must be a positive integer or known value (got " + strconv.Quote(e.val) + ")"
}

func errEnv(key, val string) error { return &envError{key: key, val: val} }

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func posIntEnv(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, errEnv(key, v)
	}
	return n, nil
}
