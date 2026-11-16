// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/xycxmz/xiezhi-public/server/internal/ingest"
	"github.com/xycxmz/xiezhi-public/server/internal/intent"
	"github.com/xycxmz/xiezhi-public/server/internal/rules"
)

// 控制台专用 API（后端三端点）：Agents/Rules tab 不再从事件流反推，
// Dashboard 一次拉齐。依赖缺项按仓库一贯的「缺了就降级」语义：对应字段
// 缺省并在 degraded 里点名，绝不 500。

// ConsoleCounts 是 CH 聚合计数面（store.CHStore 实现）。
type ConsoleCounts interface {
	AlertCountsByRule(ctx context.Context, since time.Time) (map[string]uint64, error)
	AlertCountsBySeverity(ctx context.Context, since time.Time) (map[string]uint64, error)
	EventCountsByType(ctx context.Context, since time.Time) (map[string]uint64, error)
}

// NamedStats 让 main 用闭包把各 handler 的异构 Stats() 收进同一端点。
type NamedStats struct {
	Name  string
	Stats func() any
}

// ConsoleDeps 全部可空；nil 的依赖产生降级标记而非报错。
type ConsoleDeps struct {
	Beats         interface{ Snapshot() []ingest.Beat } // ingest.Heartbeats
	BeatThreshold time.Duration                         // 在线判定窗口（deadman 阈值同源）
	Rules         interface {
		RuleSnapshot() []rules.RuleInfo
		Stats() rules.Stats
	} // *rules.Engine
	IntentStats func() any // *intent.Handler.Stats 适配（可空）
	Counts      ConsoleCounts
	// TreeDrill 是溯源图一期（告警钻取进程树）：入参告警键，返回
	// {found, tree, nodes, reason}。可空时 /api/alert/tree 报降级。
	TreeDrill func(ctx context.Context, tsMs int64, ruleID, agentID string) (any, error)
	// LLMUsage 返回近 24h 研判用量（count/tokens_in/tokens_out/
	// avg_latency_ms）；可空时 stats 不含该段。
	LLMUsage func(ctx context.Context) (map[string]uint64, error)
}

const consoleStatsWindow = 24 * time.Hour

// RegisterConsoleAPI 把 /api/agents /api/rules /api/stats 挂到 mux。
// 须在 auth.Middleware 包裹前挂载（与 /events /alerts 同保护面）。
func RegisterConsoleAPI(mux *http.ServeMux, deps ConsoleDeps) {
	mux.HandleFunc("GET /api/agents", func(w http.ResponseWriter, r *http.Request) {
		handleConsoleAgents(w, deps)
	})
	mux.HandleFunc("GET /api/rules", func(w http.ResponseWriter, r *http.Request) {
		handleConsoleRules(w, r, deps)
	})
	mux.HandleFunc("GET /api/stats", func(w http.ResponseWriter, r *http.Request) {
		handleConsoleStats(w, r, deps)
	})
	mux.HandleFunc("GET /api/alert/tree", func(w http.ResponseWriter, r *http.Request) {
		handleAlertTree(w, r, deps)
	})
}

func handleConsoleAgents(w http.ResponseWriter, deps ConsoleDeps) {
	threshold := deps.BeatThreshold
	if threshold <= 0 {
		threshold = 90 * time.Second
	}
	now := time.Now().UnixMilli()
	type agentJSON struct {
		AgentID    string `json:"agent_id"`
		Hostname   string `json:"hostname"`
		InstanceID string `json:"instance_id"`
		LastMs     int64  `json:"last_ms"`
		Online     bool   `json:"online"`
	}
	resp := struct {
		ThresholdSec int64       `json:"threshold_sec"`
		Agents       []agentJSON `json:"agents"`
	}{ThresholdSec: int64(threshold.Seconds()), Agents: []agentJSON{}}
	if deps.Beats != nil {
		for _, b := range deps.Beats.Snapshot() {
			resp.Agents = append(resp.Agents, agentJSON{
				AgentID: b.AgentID, Hostname: b.Hostname, InstanceID: b.InstanceID,
				LastMs: b.LastMs, Online: b.LastMs > 0 && now-b.LastMs < threshold.Milliseconds(),
			})
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleConsoleRules(w http.ResponseWriter, r *http.Request, deps ConsoleDeps) {
	type ruleJSON struct {
		ID       string `json:"id"`
		Event    string `json:"event"`
		Severity string `json:"severity"`
		Mitre    string `json:"mitre"`
		Hits24h  uint64 `json:"hits_24h"`
	}
	resp := struct {
		Rules    []ruleJSON `json:"rules"`
		Degraded []string   `json:"degraded,omitempty"`
	}{Rules: []ruleJSON{}}
	if deps.Rules == nil {
		resp.Degraded = append(resp.Degraded, "rules engine not loaded")
		writeJSON(w, http.StatusOK, resp)
		return
	}
	var hits map[string]uint64
	if deps.Counts != nil {
		if m, err := deps.Counts.AlertCountsByRule(r.Context(), time.Now().Add(-consoleStatsWindow)); err == nil {
			hits = m
		}
	}
	for _, ri := range deps.Rules.RuleSnapshot() {
		resp.Rules = append(resp.Rules, ruleJSON{
			ID: ri.ID, Event: ri.Event, Severity: ri.Severity, Mitre: ri.Mitre,
			Hits24h: hits[ri.ID],
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleConsoleStats(w http.ResponseWriter, r *http.Request, deps ConsoleDeps) {
	resp := map[string]any{
		"events_24h": map[string]uint64{},
		"alerts_24h": map[string]uint64{},
		"engines":    map[string]any{},
		"degraded":   []string{},
	}
	if deps.Counts != nil {
		since := time.Now().Add(-consoleStatsWindow)
		if m, err := deps.Counts.EventCountsByType(r.Context(), since); err == nil {
			resp["events_24h"] = m
		}
		if m, err := deps.Counts.AlertCountsBySeverity(r.Context(), since); err == nil {
			resp["alerts_24h"] = m
		}
	}
	engines := map[string]any{}
	degraded := []string{}
	if deps.Rules != nil {
		engines["rules"] = deps.Rules.Stats()
	} else {
		degraded = append(degraded, "rules engine not loaded")
	}
	if deps.IntentStats != nil {
		engines["intent"] = deps.IntentStats()
	}
	// 静默失效 watchdog 判据（04:21 停报轮教训）：事件高位持续
	// 流入而告警墙钟长期不动。只对「曾经告过警」的引擎报警且用 1h 窗——
	// 安静时段/凌晨告警少是正常形态（06:32 轮曾按计数形态误判死态）。
	degraded = append(degraded, DegradedReasons(engines)...)
	if deps.Beats != nil {
		threshold := deps.BeatThreshold
		if threshold <= 0 {
			threshold = 90 * time.Second
		}
		cut := time.Now().UnixMilli() - threshold.Milliseconds()
		online, total := 0, 0
		for _, b := range deps.Beats.Snapshot() {
			total++
			if b.LastMs > cut {
				online++
			}
		}
		resp["agents"] = map[string]int{"online": online, "total": total}
	}
	if deps.LLMUsage != nil {
		if u, err := deps.LLMUsage(r.Context()); err == nil {
			resp["llm_usage_24h"] = u
		}
	}
	resp["engines"] = engines
	resp["degraded"] = degraded
	writeJSON(w, http.StatusOK, resp)
}

// handleAlertTree 溯源图一期：告警 → 触发进程 → 所在会话树（PG 归档）。
func handleAlertTree(w http.ResponseWriter, r *http.Request, deps ConsoleDeps) {
	if deps.TreeDrill == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"found": false, "reason": "session store not loaded (XIEZHI_PG_DSN empty?)",
		})
		return
	}
	tsMs, err := strconv.ParseInt(r.URL.Query().Get("ts_ms"), 10, 64)
	ruleID := r.URL.Query().Get("rule_id")
	if err != nil || tsMs <= 0 || ruleID == "" {
		http.Error(w, `{"error":"ts_ms and rule_id required"}`, http.StatusBadRequest)
		return
	}
	out, err := deps.TreeDrill(r.Context(), tsMs, ruleID, r.URL.Query().Get("agent"))
	if err != nil {
		http.Error(w, `{"error":"drill failed"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// DegradedReasons 汇总静默失效判据（导出供 webhook 出口巡检复用，与
// /api/stats 同一判定源）。engines 形态同 stats 的 engines 段。
func DegradedReasons(engines map[string]any) []string {
	const silentAgoMs int64 = 60 * 60 * 1000
	const busyEvents = 50_000
	nowMs := time.Now().UnixMilli()
	var out []string
	if rs, ok := engines["rules"].(rules.Stats); ok &&
		rs.LastAlertMs > 0 && rs.EventsProcessed > busyEvents &&
		nowMs-rs.LastAlertMs > silentAgoMs {
		out = append(out, "rules silent: high event flow, no alert for >1h")
	}
	if is, ok := engines["intent"].(intent.Stats); ok &&
		is.LastAlertMs > 0 && is.EventsProcessed > busyEvents &&
		nowMs-is.LastAlertMs > silentAgoMs {
		out = append(out, "intent silent: high event flow, no alert for >1h")
	}
	return out
}
