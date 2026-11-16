// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// AlertHub 是告警的进程内即时广播（SSE 出口）：Broadcast O(1) 非阻塞，
// 慢消费者（订阅 chan 满）丢该订阅的当条消息，绝不阻塞检测链。
type AlertHub struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

func NewAlertHub() *AlertHub {
	return &AlertHub{subs: make(map[chan []byte]struct{})}
}

func (h *AlertHub) Broadcast(b []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- b:
		default: // 慢消费者：丢条不丢链路
		}
	}
}

func (h *AlertHub) subscribe() (chan []byte, func()) {
	ch := make(chan []byte, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

// RegisterStreamAPI 挂 GET /api/stream（SSE）：event: alert 推新告警 JSON
// （形态同 /alerts 行）；15s 注释心跳防中间件空闲断连。须在 auth 中间件
// 包裹前挂载（与 /alerts 同保护面）。
func RegisterStreamAPI(mux *http.ServeMux, hub *AlertHub) {
	if hub == nil {
		return
	}
	mux.HandleFunc("GET /api/stream", func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		fmt.Fprint(w, ": hello\n\n")
		fl.Flush()
		ch, cancel := hub.subscribe()
		defer cancel()
		beat := time.NewTicker(15 * time.Second)
		defer beat.Stop()
		for {
			select {
			case b := <-ch:
				fmt.Fprintf(w, "event: alert\ndata: %s\n\n", b)
				fl.Flush()
			case <-beat.C:
				fmt.Fprint(w, ": ping\n\n")
				fl.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
}

// handleAlertAck 处理 POST /api/alerts/ack {ts_ms, rule_id, agent_id}。幂等。
// agent_id 入键（S-1）：同毫秒同规则跨主机的告警须分别确认。
func handleAlertAck(w http.ResponseWriter, r *http.Request, aq AlertQuerier) {
	var body struct {
		TsMs    int64  `json:"ts_ms"`
		RuleID  string `json:"rule_id"`
		AgentID string `json:"agent_id"`
		By      string `json:"by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.TsMs == 0 || body.RuleID == "" {
		http.Error(w, `{"error":"ts_ms and rule_id required"}`, http.StatusBadRequest)
		return
	}
	if err := aq.AckAlert(r.Context(), body.TsMs, body.RuleID, body.AgentID, body.By); err != nil {
		http.Error(w, `{"error":"ack failed"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
