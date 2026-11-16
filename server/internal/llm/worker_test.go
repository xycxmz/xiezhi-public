// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type fakeStore struct {
	mu   sync.Mutex
	rows []TriageRow
	err  error
}

func (f *fakeStore) SaveTriage(_ context.Context, r TriageRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.rows = append(f.rows, r)
	return nil
}

func (f *fakeStore) len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rows)
}

func (f *fakeStore) last() TriageRow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rows[len(f.rows)-1]
}

// trackingProvider 记录在飞峰值并可控延迟/输出，验证并发闸与超时。
type trackingProvider struct {
	mu             sync.Mutex
	delay          time.Duration
	inflight, peak int
	verdict        Verdict
	rawErr         error // 非 nil 时 Complete 返回该错误（errParse/ctx 错误路径）
	roleErr        error // 非 nil 时 CompleteRole 直接返回该错误（多角色链失败）
}

func (p *trackingProvider) Name() string { return "tracking" }

func (p *trackingProvider) Complete(ctx context.Context, _, _ string) (Completion, error) {
	p.mu.Lock()
	p.inflight++
	if p.inflight > p.peak {
		p.peak = p.inflight
	}
	delay, verdict, rawErr := p.delay, p.verdict, p.rawErr
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.inflight--
		p.mu.Unlock()
	}()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return Completion{}, ctx.Err()
		}
	}
	if rawErr != nil {
		return Completion{Raw: "not json"}, rawErr
	}
	return Completion{Verdict: verdict, TokensIn: 10, TokensOut: 5, Raw: mustJSON(verdict)}, nil
}

func (p *trackingProvider) peakInflight() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peak
}

// CompleteRole 默认把 Complete 的 verdict JSON 当原文返回——它不合 hypotheses
// schema，正好驱动「角色解析失败→降级单角色」路径；roleErr 非 nil 时硬失败。
func (p *trackingProvider) CompleteRole(ctx context.Context, _ Role, system, user string) (RoleCompletion, error) {
	if p.roleErr != nil {
		return RoleCompletion{Raw: "not json"}, p.roleErr
	}
	comp, err := p.Complete(ctx, system, user)
	if err != nil {
		return RoleCompletion{}, err
	}
	return RoleCompletion{Raw: comp.Raw, TokensIn: comp.TokensIn, TokensOut: comp.TokensOut}, nil
}

func testConfig() Config {
	return Config{
		Provider: "mock", MaxConcurrency: 2, TriageSinceMin: 15,
		Timeout: 5 * time.Second,
	}
}

func TestHandleAlertMockEndToEnd(t *testing.T) {
	store := &fakeStore{}
	fetcher := &fakeFetcher{rows: []EventSummary{
		{TsMs: time.Now().UnixMilli(), Type: "DNS_QUERY", Body: `{"queries":["evil.example"]}`},
	}}
	trees := &fakeTrees{tree: "bash\n  curl"}
	w := NewWorker(testConfig(), NewProvider(testConfig()), store, fetcher, trees)

	a := testAlert()
	w.HandleAlert(context.Background(), a)

	if got := store.len(); got != 1 {
		t.Fatalf("store rows = %d, want 1", got)
	}
	row := store.last()
	if row.RuleID != a.RuleID || row.AgentID != a.AgentID || row.AlertTsMs != a.TsMs {
		t.Errorf("row identity mismatch: %+v", row)
	}
	if row.State != StateEscalate || row.Confidence != 0.95 {
		t.Errorf("mock verdict mismatch: state=%s confidence=%v", row.State, row.Confidence)
	}
	if row.Model != "mock" {
		t.Errorf("model = %q, want mock", row.Model)
	}
	if row.TokensIn <= 0 {
		t.Errorf("tokens_in = %d, want positive", row.TokensIn)
	}
	if row.Tactic != "T1059" {
		t.Errorf("tactic = %q", row.Tactic)
	}
	stats := w.Stats()
	if stats["received"] != 1 || stats["triaged"] != 1 {
		t.Errorf("stats after one verdict: %+v", stats)
	}
}

func TestHandleAlertSkipsStaleAlert(t *testing.T) {
	store := &fakeStore{}
	w := NewWorker(testConfig(), NewMockProvider(), store, nil, nil)
	a := testAlert()
	a.TsMs = time.Now().Add(-16 * time.Minute).UnixMilli() // 窗口 15 分钟
	w.HandleAlert(context.Background(), a)
	if store.len() != 0 {
		t.Error("stale alert must not be triaged")
	}
	if w.Stats()["skipped_stale"] != 1 {
		t.Errorf("skipped_stale = %d, want 1", w.Stats()["skipped_stale"])
	}
	if w.Stats()["received"] != 1 {
		t.Error("stale alert still counts as received")
	}
}

// onMsg 是 NATS 回调与 HandleAlert 之间的唯一粘合层（fake NATS 不可行，
// 契约冻结此路径为直接驱动）：合法负载异步研判落库，坏负载只告警不计数。
func TestOnMsg(t *testing.T) {
	store := &fakeStore{}
	w := NewWorker(testConfig(), NewMockProvider(), store, nil, nil)
	defer w.Close()

	w.onMsg([]byte(`{not json`))
	if w.Stats()["received"] != 0 {
		t.Error("bad payload must not count as received")
	}

	payload, err := json.Marshal(testAlert())
	if err != nil {
		t.Fatal(err)
	}
	w.onMsg(payload)
	deadline := time.Now().Add(3 * time.Second)
	for store.len() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if store.len() != 1 || store.last().State != StateEscalate {
		t.Errorf("onMsg did not triage: rows=%d", store.len())
	}
}

func TestHandleAlertConcurrencyCap(t *testing.T) {
	p := &trackingProvider{delay: 120 * time.Millisecond, verdict: mockVerdict("x")}
	store := &fakeStore{}
	w := NewWorker(testConfig(), p, store, nil, nil) // MaxConcurrency=2
	var wg sync.WaitGroup
	const n = 8
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.HandleAlert(context.Background(), testAlert())
		}()
	}
	wg.Wait()
	if peak := p.peakInflight(); peak > 2 {
		t.Errorf("peak inflight = %d, want <= 2", peak)
	}
	if got := store.len(); got != n {
		t.Errorf("store rows = %d, want %d", got, n)
	}
}

func TestHandleAlertTimeout(t *testing.T) {
	p := &trackingProvider{delay: 3 * time.Second}
	store := &fakeStore{}
	cfg := testConfig()
	cfg.Timeout = 100 * time.Millisecond
	w := NewWorker(cfg, p, store, nil, nil)
	w.HandleAlert(context.Background(), testAlert())
	if store.len() != 0 {
		t.Error("timed-out triage must not persist")
	}
	if w.Stats()["timeout"] != 1 {
		t.Errorf("timeout = %d, want 1", w.Stats()["timeout"])
	}
}

func TestHandleAlertParseErrorPersisted(t *testing.T) {
	p := &trackingProvider{rawErr: errParse}
	store := &fakeStore{}
	w := NewWorker(testConfig(), p, store, nil, nil)
	w.HandleAlert(context.Background(), testAlert())
	if got := store.len(); got != 1 {
		t.Fatalf("parse_error must persist a row, got %d", got)
	}
	row := store.last()
	if row.State != StateParseError {
		t.Errorf("state = %s, want parse_error", row.State)
	}
	if row.Confidence != 0 {
		t.Errorf("parse_error confidence must be 0, got %v", row.Confidence)
	}
	if row.Reasoning == "" || row.TokensIn != 0 {
		t.Errorf("parse_error row should keep raw output for audit: %+v", row)
	}
	stats := w.Stats()
	if stats["parse_error"] != 1 || stats["triaged"] != 0 {
		t.Errorf("stats after parse error: %+v", stats)
	}
}

func TestHandleAlertStoreFailureCounted(t *testing.T) {
	store := &fakeStore{err: errors.New("ch down")}
	w := NewWorker(testConfig(), NewMockProvider(), store, nil, nil)
	w.HandleAlert(context.Background(), testAlert())
	if w.Stats()["store_failed"] != 1 {
		t.Errorf("store_failed = %d, want 1", w.Stats()["store_failed"])
	}
	if w.Stats()["triaged"] != 0 {
		t.Error("failed save must not count as triaged")
	}
}

// openaiProvider 的协议与重试语义走本地 httptest 假端点（不调真实 LLM）：
// 第一次返回非 JSON、第二次返回合法 verdict，断言恰好重试 1 次且请求带
// temperature=0、response_format json_object、Bearer key。
func TestOpenAIProviderRetryOnBadJSON(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	var lastBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" || r.Header.Get("Authorization") != "Bearer test-key" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		calls++
		lastBody = body
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"not json at all"}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"state\":\"escalate\",\"confidence\":0.8,\"reasoning\":\"r\",\"tactic\":\"T1059\"}"}}],"usage":{"prompt_tokens":42,"completion_tokens":7}}`))
	}))
	defer srv.Close()

	p := NewOpenAIProvider(srv.URL, "test-key", "test-model")
	comp, err := p.Complete(context.Background(), "sys", "user")
	if err != nil {
		t.Fatal(err)
	}
	if comp.Verdict.State != StateEscalate || comp.Verdict.Confidence != 0.8 {
		t.Errorf("verdict = %+v", comp.Verdict)
	}
	if comp.TokensIn != 42 || comp.TokensOut != 7 {
		t.Errorf("tokens = %d/%d, want 42/7", comp.TokensIn, comp.TokensOut)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2 (retry once)", calls)
	}
	if lastBody["temperature"] != float64(0) {
		t.Errorf("temperature = %v, want 0", lastBody["temperature"])
	}
	if rf, _ := lastBody["response_format"].(map[string]any); rf == nil || rf["type"] != "json_object" {
		t.Errorf("response_format = %v, want json_object", lastBody["response_format"])
	}
}

func TestOpenAIProviderGivesUpAfterRetry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"garbage"}}]}`))
	}))
	defer srv.Close()
	p := NewOpenAIProvider(srv.URL, "k", "m")
	_, err := p.Complete(context.Background(), "sys", "user")
	if !errors.Is(err, errParse) {
		t.Errorf("err = %v, want errParse after one retry", err)
	}
}
