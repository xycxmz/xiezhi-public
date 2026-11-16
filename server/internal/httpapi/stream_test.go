// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/xycxmz/xiezhi-public/server/internal/store"
)

type fakeAckStore struct {
	mu     sync.Mutex
	acked  map[string]bool
	alerts []map[string]any
}

func (f *fakeAckStore) RecentAlerts(_ context.Context, _ store.AlertQuery) ([]map[string]any, error) {
	return f.alerts, nil
}

func (f *fakeAckStore) AckAlert(_ context.Context, tsMs int64, ruleID, agentID, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acked[fmt.Sprintf("%d|%s|%s", tsMs, ruleID, agentID)] = true
	return nil
}

func (f *fakeAckStore) AckedKeys(_ context.Context) (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]bool{}
	for k := range f.acked {
		out[k] = true
	}
	return out, nil
}

// S-1：ack 键必须含 agent_id——firstseen digest 批量告警会同毫秒同规则
// 跨主机触发，ack 一条不得连带隐藏他机告警。
func TestAlertAckKeyIncludesAgent(t *testing.T) {
	f := &fakeAckStore{acked: map[string]bool{}, alerts: []map[string]any{
		{"ts_ms": int64(1), "rule_id": "r1", "agent_id": "agent-a"},
		{"ts_ms": int64(1), "rule_id": "r1", "agent_id": "agent-b"},
	}}
	mux := http.NewServeMux()
	NewWithAlertsMux(nil, f, mux)

	body := `{"ts_ms":1,"rule_id":"r1","agent_id":"agent-a"}`
	req := httptest.NewRequest(http.MethodPost, "/api/alerts/ack", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ack = %d: %s", rec.Code, rec.Body.String())
	}

	// hide 视角：agent-b 的同 (ts_ms, rule_id) 告警必须仍可见
	req = httptest.NewRequest(http.MethodGet, "/alerts?acked=hide", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var rows []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&rows); err != nil || len(rows) != 1 {
		t.Fatalf("acked=hide rows=%v err=%v", rows, err)
	}
	if rows[0]["agent_id"] != "agent-b" {
		t.Fatalf("survivor = %v, want agent-b", rows[0]["agent_id"])
	}
}

// ack 端点校验与过滤三视角（show/hide/only）——R6.4 确认工作流的验收线。
func TestAlertAckAndFilter(t *testing.T) {
	f := &fakeAckStore{acked: map[string]bool{}, alerts: []map[string]any{
		{"ts_ms": int64(1), "rule_id": "r1", "agent_id": "a1"},
		{"ts_ms": int64(2), "rule_id": "r2", "agent_id": "a1"},
	}}
	mux := http.NewServeMux()
	NewWithAlertsMux(nil, f, mux)

	// 空 body 拒 400
	req := httptest.NewRequest(http.MethodPost, "/api/alerts/ack", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body = %d, want 400", rec.Code)
	}

	// ack r1 后 hide 只剩 r2、only 只剩 r1
	body := `{"ts_ms":1,"rule_id":"r1","agent_id":"a1"}`
	req = httptest.NewRequest(http.MethodPost, "/api/alerts/ack", strings.NewReader(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ack = %d: %s", rec.Code, rec.Body.String())
	}
	for mode, wantRule := range map[string]string{"hide": "r2", "only": "r1"} {
		req = httptest.NewRequest(http.MethodGet, "/alerts?acked="+mode, nil)
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var rows []map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&rows); err != nil || len(rows) != 1 {
			t.Fatalf("acked=%s rows=%v err=%v", mode, rows, err)
		}
		if rows[0]["rule_id"] != wantRule {
			t.Fatalf("acked=%s got %v want %s", mode, rows[0]["rule_id"], wantRule)
		}
	}
}
