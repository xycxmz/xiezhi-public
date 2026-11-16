// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeReader struct {
	got TriageQuery
	err error
}

func (f *fakeReader) RecentTriages(_ context.Context, q TriageQuery) ([]map[string]any, error) {
	f.got = q
	if f.err != nil {
		return nil, f.err
	}
	return []map[string]any{{"rule_id": "exec-curl-pipe-shell", "state": "escalate"}}, nil
}

type fakeStats struct{ n uint64 }

func (f fakeStats) Stats() map[string]uint64 { return map[string]uint64{"received": f.n} }

func TestTriageHandlerQuery(t *testing.T) {
	rd := &fakeReader{}
	h := TriageHandler(rd, fakeStats{n: 3})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/triage?limit=7&state=escalate&rule=exec-curl-pipe-shell", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if rd.got.Limit != 7 || rd.got.State != "escalate" || rd.got.RuleID != "exec-curl-pipe-shell" {
		t.Errorf("query passed through wrong: %+v", rd.got)
	}
	var rows []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil || len(rows) != 1 {
		t.Errorf("rows = %s err = %v", rec.Body.String(), err)
	}
}

func TestTriageHandlerBadLimit(t *testing.T) {
	h := TriageHandler(&fakeReader{}, nil)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/triage?limit=0", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("limit=0 code = %d, want 400", rec.Code)
	}
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/triage?limit=abc", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("limit=abc code = %d, want 400", rec.Code)
	}
}

func TestTriageHandlerStats(t *testing.T) {
	h := TriageHandler(nil, fakeStats{n: 42})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/triage?stats=1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var m map[string]uint64
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || m["received"] != 42 {
		t.Errorf("stats = %s err = %v", rec.Body.String(), err)
	}
}

func TestTriageHandlerUnwired(t *testing.T) {
	rec := httptest.NewRecorder()
	TriageHandler(nil, nil)(rec, httptest.NewRequest(http.MethodGet, "/triage", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("reader-nil code = %d, want 503", rec.Code)
	}
	rec = httptest.NewRecorder()
	TriageHandler(nil, nil)(rec, httptest.NewRequest(http.MethodGet, "/triage?stats=1", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("stats-nil code = %d, want 503", rec.Code)
	}
}
