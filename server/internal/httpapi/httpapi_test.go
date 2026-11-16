// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xycxmz/xiezhi-public/server/internal/store"
)

type fakeQuerier struct {
	called bool
	gotQry store.Query
	rows   []store.Row
	err    error
}

func (f *fakeQuerier) RecentEvents(_ context.Context, q store.Query) ([]store.Row, error) {
	f.called = true
	f.gotQry = q
	return f.rows, f.err
}

func get(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestHealthz(t *testing.T) {
	srv := httptest.NewServer(New(&fakeQuerier{}))
	defer srv.Close()
	resp := get(t, srv.URL+"/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Fatalf("body = %v", body)
	}
}

func TestEventsParams(t *testing.T) {
	cases := []struct {
		name       string
		query      string
		wantStatus int
		wantLimit  int
		wantAgent  string
		wantType   string
		wantCalled bool
	}{
		{"defaults", "", http.StatusOK, 100, "", "", true},
		{"limit 50", "limit=50", http.StatusOK, 50, "", "", true},
		{"limit clamped to 1000", "limit=99999", http.StatusOK, 1000, "", "", true},
		{"filters", "agent=a1&type=EXECVE", http.StatusOK, 100, "a1", "EXECVE", true},
		{"limit 0", "limit=0", http.StatusBadRequest, 0, "", "", false},
		{"limit not a number", "limit=abc", http.StatusBadRequest, 0, "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := &fakeQuerier{}
			srv := httptest.NewServer(New(q))
			defer srv.Close()
			resp := get(t, srv.URL+"/events?"+tc.query)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if q.called != tc.wantCalled {
				t.Fatalf("querier called = %v, want %v", q.called, tc.wantCalled)
			}
			if tc.wantCalled {
				if q.gotQry.Limit != tc.wantLimit || q.gotQry.Agent != tc.wantAgent || q.gotQry.Type != tc.wantType {
					t.Fatalf("query = %+v, want limit=%d agent=%q type=%q", q.gotQry, tc.wantLimit, tc.wantAgent, tc.wantType)
				}
			}
		})
	}
}

func TestEventsResponseShape(t *testing.T) {
	q := &fakeQuerier{rows: []store.Row{{
		Ts:        time.UnixMilli(1000).UTC(),
		AgentID:   "a",
		Hostname:  "h",
		EventType: "EXECVE",
		Body:      `{"seq":1}`,
	}}}
	srv := httptest.NewServer(New(q))
	defer srv.Close()

	resp := get(t, srv.URL+"/events?limit=5")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var events []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	e := events[0]
	if e["ts"] != "1970-01-01T00:00:01Z" {
		t.Fatalf("ts = %v", e["ts"])
	}
	if e["agent_id"] != "a" || e["hostname"] != "h" || e["event_type"] != "EXECVE" {
		t.Fatalf("event fields = %v", e)
	}
	body, _ := e["body"].(map[string]any)
	if body["seq"] != float64(1) {
		t.Fatalf("body must be the inlined event JSON, got %v", e["body"])
	}
}

func TestEventsQuerierError(t *testing.T) {
	q := &fakeQuerier{err: errors.New("ch down")}
	srv := httptest.NewServer(New(q))
	defer srv.Close()
	resp := get(t, srv.URL+"/events")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestEventsEmptyResultIsJSONArray(t *testing.T) {
	q := &fakeQuerier{}
	srv := httptest.NewServer(New(q))
	defer srv.Close()
	resp := get(t, srv.URL+"/events")
	var events []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	if events == nil || len(events) != 0 {
		t.Fatalf("empty result must be [], got %v", events)
	}
}
