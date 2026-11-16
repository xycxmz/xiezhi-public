// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xycxmz/xiezhi-public/server/internal/ingest"
	"github.com/xycxmz/xiezhi-public/server/internal/rules"
)

func TestConsoleAgentsOnlineCalc(t *testing.T) {
	hb := ingest.NewHeartbeats()
	hb.Record("a1", "h1", "i-1", time.Now().UnixMilli())
	hb.Record("a2", "h2", "", time.Now().Add(-10*time.Minute).UnixMilli())

	mux := http.NewServeMux()
	RegisterConsoleAPI(mux, ConsoleDeps{Beats: hb, BeatThreshold: 90 * time.Second})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/agents")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got struct {
		ThresholdSec int64 `json:"threshold_sec"`
		Agents       []struct {
			AgentID string `json:"agent_id"`
			Online  bool   `json:"online"`
		} `json:"agents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ThresholdSec != 90 {
		t.Fatalf("threshold_sec = %d, want 90", got.ThresholdSec)
	}
	if len(got.Agents) != 2 {
		t.Fatalf("agents = %d, want 2", len(got.Agents))
	}
	byID := map[string]bool{}
	for _, a := range got.Agents {
		byID[a.AgentID] = a.Online
	}
	if !byID["a1"] || byID["a2"] {
		t.Fatalf("online flags = %v, want a1=true a2=false", byID)
	}
}

func TestConsoleRulesDegraded(t *testing.T) {
	mux := http.NewServeMux()
	RegisterConsoleAPI(mux, ConsoleDeps{}) // 全空依赖：降级不 500
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/rules")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded)", resp.StatusCode)
	}
	var got struct {
		Rules    []rules.RuleInfo `json:"rules"`
		Degraded []string         `json:"degraded"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 0 || len(got.Degraded) == 0 {
		t.Fatalf("rules=%d degraded=%v, want empty rules with degraded marker", len(got.Rules), got.Degraded)
	}
}

func TestConsoleStatsShape(t *testing.T) {
	hb := ingest.NewHeartbeats()
	hb.Record("a1", "h1", "", time.Now().UnixMilli())
	counts := fakeCounts{
		alertsByRule:     map[string]uint64{"exec-x": 3},
		alertsBySeverity: map[string]uint64{"high": 1, "medium": 2},
		eventsByType:     map[string]uint64{"EXECVE": 10},
	}
	mux := http.NewServeMux()
	RegisterConsoleAPI(mux, ConsoleDeps{Beats: hb, Counts: counts})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got struct {
		Events24h map[string]uint64 `json:"events_24h"`
		Alerts24h map[string]uint64 `json:"alerts_24h"`
		Agents    map[string]int    `json:"agents"`
		Degraded  []string          `json:"degraded"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Events24h["EXECVE"] != 10 || got.Alerts24h["high"] != 1 {
		t.Fatalf("counts = %v %v", got.Events24h, got.Alerts24h)
	}
	if got.Agents["online"] != 1 || got.Agents["total"] != 1 {
		t.Fatalf("agents = %v", got.Agents)
	}
	if len(got.Degraded) == 0 {
		t.Fatal("degraded should name the missing rules engine")
	}
}

type fakeCounts struct {
	alertsByRule     map[string]uint64
	alertsBySeverity map[string]uint64
	eventsByType     map[string]uint64
}

func (f fakeCounts) AlertCountsByRule(_ context.Context, _ time.Time) (map[string]uint64, error) {
	return f.alertsByRule, nil
}
func (f fakeCounts) AlertCountsBySeverity(_ context.Context, _ time.Time) (map[string]uint64, error) {
	return f.alertsBySeverity, nil
}
func (f fakeCounts) EventCountsByType(_ context.Context, _ time.Time) (map[string]uint64, error) {
	return f.eventsByType, nil
}
