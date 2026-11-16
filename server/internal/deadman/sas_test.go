// SPDX-License-Identifier: Apache-2.0

package deadman

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPercentEncode(t *testing.T) {
	cases := map[string]string{
		// 阿里云规则：空格=%20（非 +）、*=%2A、~=~、字母数字与 -_.~ 不动
		"a b":                  "a%20b",
		"a*b":                  "a%2Ab",
		"~tilde":               "~tilde",
		"2026-11-12T00:00:00Z": "2026-11-12T00%3A00%3A00Z",
		"key=x&y=z":            "key%3Dx%26y%3Dz",
	}
	for in, want := range cases {
		if got := percentEncode(in); got != want {
			t.Errorf("percentEncode(%q) = %q, want %q", in, got, want)
		}
	}
}

// golden 由独立实现（python urllib+hmac）算出，
// 锁定 canonical query 排序与 string-to-sign 拼接形态。
func TestSignRPCGolden(t *testing.T) {
	params := map[string]string{
		"AccessKeyId":      "testak",
		"Action":           "DescribeCloudCenterInstances",
		"CurrentPage":      "1",
		"Format":           "JSON",
		"PageSize":         "100",
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   "nonce-1",
		"SignatureVersion": "1.0",
		"Timestamp":        "2026-11-12T00:00:00Z",
		"Version":          "2018-12-03",
	}
	want := "JFKJdExlxVdLGT1axuUANC586X0="
	if got := signRPC(params, "testsk"); got != want {
		t.Fatalf("signRPC = %q, want %q", got, want)
	}
	wantQS := "AccessKeyId=testak&Action=DescribeCloudCenterInstances&CurrentPage=1&Format=JSON&PageSize=100" +
		"&SignatureMethod=HMAC-SHA1&SignatureNonce=nonce-1&SignatureVersion=1.0&Timestamp=2026-11-12T00%3A00%3A00Z&Version=2018-12-03"
	if got := encodeParams(params); got != wantQS {
		t.Fatalf("canonical query unsorted or mis-encoded:\n got %s\nwant %s", got, wantQS)
	}
}

func TestDecodeInstancesBothShapes(t *testing.T) {
	arr, err := decodeInstances(json.RawMessage(
		`[{"InstanceId":"i-1","Uuid":"u-1","ClientStatus":"offline","Status":"notRunning"}]`))
	if err != nil || len(arr) != 1 || arr[0].InstanceID != "i-1" || arr[0].Uuid != "u-1" {
		t.Fatalf("array form: %+v err=%v", arr, err)
	}
	wrapped, err := decodeInstances(json.RawMessage(
		`{"Instance":[{"InstanceId":"i-2","Status":"running","ClientStatus":"online"}]}`))
	if err != nil || len(wrapped) != 1 || wrapped[0].Status != "running" {
		t.Fatalf("wrapped form: %+v err=%v", wrapped, err)
	}
	if got, err := decodeInstances(nil); err != nil || got != nil {
		t.Fatalf("empty payload: %+v err=%v", got, err)
	}
}

func TestClassifyPower(t *testing.T) {
	cases := []struct {
		status, client, want string
	}{
		{"running", "online", powerRunning},
		{"running", "offline", powerRunning}, // 云说开着：哪怕 aegis 离线也告警（对账以电源为准）
		{"notRunning", "offline", powerStopped},
		{"notRunning", "online", powerStopped},
		{"UNKNOWN", "offline", powerStopped}, // 契约：UNKNOWN+clientStatus offline = 关机机
		{"UNKNOWN", "online", powerUnknown},  // aegis 报在线但电源不明 → 告警侧
		{"", "offline", powerStopped},
		{"", "online", powerUnknown},
		{"Stopping", "online", powerUnknown}, // 未见过的状态值不冒充关机
		{"RUNNING", "ONLINE", powerRunning},  // 大小写不敏感
	}
	for _, tc := range cases {
		if got := classifyPower(tc.status, tc.client); got != tc.want {
			t.Errorf("classifyPower(%q,%q) = %q, want %q", tc.status, tc.client, got, tc.want)
		}
	}
}

type fakeSource struct {
	mu      sync.Mutex
	fetches int
	insts   []sasInstance
	err     error
	hook    func() // fetch 期间回调（测试「对账途中来了心跳」的竞态）
}

func (f *fakeSource) fetchAll(context.Context) ([]sasInstance, error) {
	f.mu.Lock()
	f.fetches++
	f.mu.Unlock()
	if f.hook != nil {
		f.hook()
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.insts, nil
}

func (f *fakeSource) fetchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches
}

func newFakeReconciler(insts []sasInstance) (*Reconciler, *fakeSource) {
	src := &fakeSource{insts: insts}
	return NewReconciler(src), src
}

func TestReconcilerCacheTTL(t *testing.T) {
	base := time.Now()
	clock := base
	recon, src := newFakeReconciler([]sasInstance{
		{InstanceID: "i-1", Uuid: "agent-a", Status: "running"},
		{InstanceID: "agent-b", Status: "notRunning", ClientStatus: "offline"},
	})
	recon.now = func() time.Time { return clock }

	ctx := context.Background()
	st, stale := recon.State(ctx, "agent-a")
	if st != powerRunning || stale {
		t.Fatalf("state = %q stale=%v, want running/false", st, stale)
	}
	st, _ = recon.State(ctx, "agent-b")
	if st != powerStopped {
		t.Fatalf("instance-id key match failed: %q", st)
	}
	st, _ = recon.State(ctx, "no-such-agent")
	if st != powerNotFound {
		t.Fatalf("unknown agent = %q, want not_found", st)
	}
	if n := src.fetchCount(); n != 1 {
		t.Fatalf("fetches within TTL = %d, want 1", n)
	}

	clock = base.Add(cacheTTL + time.Second)
	recon.State(ctx, "agent-a")
	if n := src.fetchCount(); n != 2 {
		t.Fatalf("fetches after TTL = %d, want 2", n)
	}
}

func TestReconcilerFetchFailureKeepsOldCache(t *testing.T) {
	base := time.Now()
	clock := base
	recon, src := newFakeReconciler([]sasInstance{
		{Uuid: "agent-a", Status: "notRunning", ClientStatus: "offline"},
	})
	recon.now = func() time.Time { return clock }
	ctx := context.Background()

	if st, _ := recon.State(ctx, "agent-a"); st != powerStopped {
		t.Fatalf("initial state = %q, want stopped", st)
	}

	src.err = fmt.Errorf("sas unreachable")
	clock = base.Add(cacheTTL + time.Second)
	st, stale := recon.State(ctx, "agent-a")
	if st != powerStopped || !stale {
		t.Fatalf("degraded state = %q stale=%v, want stopped/true (old cache)", st, stale)
	}
	// 失败退避：fetchedAt 推进，TTL 内不重试（防单轮扫描 N×30s 放大）
	recon.State(ctx, "agent-a")
	if n := src.fetchCount(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (no retry within TTL after failure)", n)
	}

	// TTL 过后再重试；恢复成功即回到新鲜缓存
	clock = base.Add(2*cacheTTL + 2*time.Second)
	src.err = nil
	st, stale = recon.State(ctx, "agent-a")
	if st != powerStopped || stale {
		t.Fatalf("recovered state = %q stale=%v, want stopped/false", st, stale)
	}
	if n := src.fetchCount(); n != 3 {
		t.Fatalf("fetches = %d, want 3 (retry after TTL)", n)
	}
}

func TestReconcilerNoSourceIsNotFound(t *testing.T) {
	recon := NewReconciler(nil)
	st, stale := recon.State(context.Background(), "anyone")
	if st != powerNotFound || stale {
		t.Fatalf("nil source: %q stale=%v, want not_found/false", st, stale)
	}
}

// 真 HTTP 往返：签名参数、分页判据（页大小<100 即止）、HTTPS endpoint 形态
// （httptest 走 http，endpoint 直接传 ts.URL 不加 https:// 前缀）。
func TestSASClientPaginationAndSigning(t *testing.T) {
	page1 := make([]sasInstance, sasPageSize)
	for i := range page1 {
		page1[i] = sasInstance{InstanceID: fmt.Sprintf("i-%d", i), Uuid: fmt.Sprintf("u-%d", i), Status: "running"}
	}
	page2 := []sasInstance{{InstanceID: "i-last", Uuid: "u-last", Status: "notRunning", ClientStatus: "offline"}}

	var hits []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		hits = append(hits, q.Get("CurrentPage"))
		if q.Get("Signature") == "" || q.Get("AccessKeyId") != "testak" || q.Get("Action") != "DescribeCloudCenterInstances" {
			t.Errorf("request missing signature/ak/action: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		if q.Get("CurrentPage") == "1" {
			json.NewEncoder(w).Encode(map[string]any{"Instances": page1, "PageInfo": map[string]int{"Total": len(page1) + 1}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"Instances": page2, "PageInfo": map[string]int{"Total": len(page1) + 1}})
	}))
	defer ts.Close()

	c := newSASClient("testak", "testsk", ts.URL)
	c.nonce = func() string { return "fixed-nonce" }
	insts, err := c.fetchAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(insts) != len(page1)+1 {
		t.Fatalf("fetched = %d, want %d", len(insts), len(page1)+1)
	}
	if insts[len(insts)-1].InstanceID != "i-last" {
		t.Fatal("second page not merged in order")
	}
	if len(hits) != 2 || hits[0] != "1" || hits[1] != "2" {
		t.Fatalf("pages hit = %v, want [1 2]", hits)
	}
}

func TestSASClientHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"Message":"InvalidAccessKeyId"}`, http.StatusBadRequest)
	}))
	defer ts.Close()
	c := newSASClient("bad", "bad", ts.URL)
	if _, err := c.fetchAll(context.Background()); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("err = %v, want http 400 surfaced", err)
	}
}
