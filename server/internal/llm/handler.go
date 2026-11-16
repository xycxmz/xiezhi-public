// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// TriageHandler 挂 /triage：无参（或带 limit/state/rule）查最近研判；
// stats=1 输出计数器快照。stats 为 nil 时 stats=1 返回 503（装配缺指标源）。
// httpapi 包不是本包域，main 用 mux.Handle("GET /triage", llm.TriageHandler(...)) 挂载。
func TriageHandler(reader TriageReader, stats StatsSource) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("stats") != "" {
			if stats == nil {
				http.Error(w, "stats source not wired", http.StatusServiceUnavailable)
				return
			}
			writeJSON(w, http.StatusOK, stats.Stats())
			return
		}
		if reader == nil {
			http.Error(w, "triage reader not wired", http.StatusServiceUnavailable)
			return
		}
		limit := 100
		if s := r.URL.Query().Get("limit"); s != "" {
			v, err := strconv.Atoi(s)
			if err != nil || v < 1 {
				http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
				return
			}
			limit = v
		}
		rows, err := reader.RecentTriages(r.Context(), TriageQuery{
			Limit:  limit,
			State:  r.URL.Query().Get("state"),
			RuleID: r.URL.Query().Get("rule"),
		})
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

// StatsSource 是 /triage?stats=1 的指标源；*Worker 实现。
type StatsSource interface {
	Stats() map[string]uint64
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
