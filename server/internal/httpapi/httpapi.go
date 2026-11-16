// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/xycxmz/xiezhi-public/server/internal/store"
)

const (
	defaultLimit = 100
	maxLimit     = 1000
)

func New(querier store.Querier) http.Handler {
	return newWithAlerts(querier, nil)
}

// AlertQuerier 与 store.CHStore 的告警域能力对齐（测试注入用）。
// AckAlert/AckedKeys 是 R6.4 告警确认工作流（dev 语义：fake 可空实现）；
// ack 键 = (ts_ms, rule_id, agent_id) 三段（S-1：同毫秒同规则跨主机不互掩）。
type AlertQuerier interface {
	RecentAlerts(ctx context.Context, q store.AlertQuery) ([]map[string]any, error)
	AckAlert(ctx context.Context, tsMs int64, ruleID, agentID, by string) error
	AckedKeys(ctx context.Context) (map[string]bool, error)
}

// NewWithAlerts 挂 /alerts 端点（nil alertQuerier 时不注册）。
func NewWithAlerts(querier store.Querier, alertQuerier AlertQuerier) http.Handler {
	mux := http.NewServeMux()
	NewWithAlertsMux(querier, alertQuerier, mux)
	return mux
}

// NewWithAlertsMux 同 NewWithAlerts 但挂到调用方 mux（main 在其上再挂 /triage 等）。
// auth 为 nil 时跳过鉴权（开发模式）；非 nil 时全部端点（除 /login 与 /healthz）受保护。
func NewWithAlertsMux(querier store.Querier, alertQuerier AlertQuerier, mux *http.ServeMux) {
	NewWithAuth(querier, alertQuerier, mux, nil)
}

// NewWithAuth 完整装配（含鉴权中间件）。auth 为 nil 时跳过鉴权。
func NewWithAuth(querier store.Querier, alertQuerier AlertQuerier, mux *http.ServeMux, auth *AuthManager) http.Handler {
	if mux == nil {
		mux = http.NewServeMux()
	}
	registerConsole(mux)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		handleEvents(w, r, querier)
	})
	if alertQuerier != nil {
		mux.HandleFunc("GET /alerts", func(w http.ResponseWriter, r *http.Request) {
			handleAlerts(w, r, alertQuerier)
		})
		mux.HandleFunc("POST /api/alerts/ack", func(w http.ResponseWriter, r *http.Request) {
			handleAlertAck(w, r, alertQuerier)
		})
	}
	if auth != nil {
		mux.HandleFunc("GET /login", auth.HandleLogin)
		mux.HandleFunc("POST /api/auth/login", auth.HandleLogin)
		mux.HandleFunc("POST /api/auth/logout", auth.HandleLogout)
		return auth.Middleware(mux)
	}
	return mux
}

// 兼容旧签名路径（New 保持原行为）。
func newWithAlerts(querier store.Querier, aq AlertQuerier) http.Handler {
	return NewWithAlerts(querier, aq)
}

func handleAlerts(w http.ResponseWriter, r *http.Request, aq AlertQuerier) {
	limit := defaultLimit
	if s := r.URL.Query().Get("limit"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 {
			http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
			return
		}
		if v > maxLimit {
			v = maxLimit
		}
		limit = v
	}
	rows, err := aq.RecentAlerts(r.Context(), store.AlertQuery{
		Limit:    limit,
		RuleID:   r.URL.Query().Get("rule"),
		Severity: r.URL.Query().Get("severity"),
		AgentID:  r.URL.Query().Get("agent"),
	})
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	// acked=hide 过滤已确认（控制台默认视角）；acked=only 只看已确认；
	// 缺省 show 全量（evaluate.sh 等历史调用方行为不变）。
	switch r.URL.Query().Get("acked") {
	case "hide", "only":
		acked, err := aq.AckedKeys(r.Context())
		if err != nil {
			http.Error(w, "acked query failed", http.StatusInternalServerError)
			return
		}
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			// 三段键与 AckedKeys 对齐（S-1）：row["agent_id"] 由 RecentAlerts 恒填充
			k := fmt.Sprintf("%d|%s|%s", row["ts_ms"], row["rule_id"], row["agent_id"])
			_, isAcked := acked[k]
			if isAcked != (r.URL.Query().Get("acked") == "only") {
				continue
			}
			out = append(out, row)
		}
		rows = out
	}
	writeJSON(w, http.StatusOK, rows)
}

func handleEvents(w http.ResponseWriter, r *http.Request, querier store.Querier) {
	limit := defaultLimit
	if s := r.URL.Query().Get("limit"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 {
			http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
			return
		}
		if v > maxLimit {
			v = maxLimit
		}
		limit = v
	}
	q := store.Query{
		Limit: limit,
		Agent: r.URL.Query().Get("agent"),
		Type:  r.URL.Query().Get("type"),
	}
	rows, err := querier.RecentEvents(r.Context(), q)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, toEvents(rows))
}

type eventJSON struct {
	Ts        string          `json:"ts"`
	AgentID   string          `json:"agent_id"`
	Hostname  string          `json:"hostname"`
	EventType string          `json:"event_type"`
	Body      json.RawMessage `json:"body"` // 事件 JSON 全文内联，不再转义成字符串
}

func toEvents(rows []store.Row) []eventJSON {
	out := make([]eventJSON, len(rows))
	for i, r := range rows {
		out[i] = eventJSON{
			Ts:        r.Ts.UTC().Format(time.RFC3339Nano),
			AgentID:   r.AgentID,
			Hostname:  r.Hostname,
			EventType: r.EventType,
			Body:      json.RawMessage(r.Body),
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
