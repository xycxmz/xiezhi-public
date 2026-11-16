// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xycxmz/xiezhi-public/server/internal/store"
)

func TestConsolePage(t *testing.T) {
	mux := http.NewServeMux()
	registerConsole(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := get(t, srv.URL+"/console")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q, want text/html", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	page := string(body)
	for _, tab := range []string{
		`data-tab="dashboard"`, `data-tab="events"`, `data-tab="alerts"`,
		`data-tab="triage"`, `data-tab="agents"`, `data-tab="rules"`,
	} {
		if !strings.Contains(page, tab) {
			t.Fatalf("page missing tab marker %s", tab)
		}
	}
}

func TestConsoleRootRedirects(t *testing.T) {
	mux := http.NewServeMux()
	registerConsole(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(_ *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/console" {
		t.Fatalf("location = %q, want /console", loc)
	}
}

// TestConsoleAuthFlow 走完整鉴权链：未登录 HTML 跳 /login、API 401、
// 登录换 cookie、cookie 下 console/events 可用、登出后失效。
func TestConsoleAuthFlow(t *testing.T) {
	q := &fakeQuerier{rows: []store.Row{{
		Ts: time.Now(), AgentID: "a1", Hostname: "h1",
		EventType: "EXECVE", Body: `{"agentId":"a1"}`,
	}}}
	srv := httptest.NewServer(NewWithAuth(q, nil, http.NewServeMux(), NewAuthManager("pw")))
	defer srv.Close()

	noRedirect := &http.Client{CheckRedirect: func(_ *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := noRedirect.Get(srv.URL + "/console")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("unauth /console = %d %q, want 303 /login", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, err = noRedirect.Get(srv.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth /events = %d, want 401", resp.StatusCode)
	}

	login := func(pw string) *http.Response {
		t.Helper()
		r, err := noRedirect.PostForm(srv.URL+"/api/auth/login", map[string][]string{"password": {pw}})
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r
	}
	if r := login("wrong"); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login = %d, want 401", r.StatusCode)
	}
	r := login("pw")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("login = %d, want 200", r.StatusCode)
	}
	cookie := r.Header.Get("Set-Cookie")
	if !strings.Contains(cookie, "xiezhi_session=") {
		t.Fatalf("login set-cookie = %q, want xiezhi_session", cookie)
	}
	token := strings.SplitN(strings.Split(cookie, ";")[0], "=", 2)[1]

	authed := &http.Client{CheckRedirect: func(_ *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/console", nil)
	req.AddCookie(&http.Cookie{Name: "xiezhi_session", Value: token})
	pageResp, err := authed.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer pageResp.Body.Close()
	if pageResp.StatusCode != http.StatusOK {
		t.Fatalf("authed /console = %d, want 200", pageResp.StatusCode)
	}
	body, err := io.ReadAll(pageResp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `data-tab="dashboard"`) {
		t.Fatal("authed console page missing dashboard tab")
	}

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/events", nil)
	req.AddCookie(&http.Cookie{Name: "xiezhi_session", Value: token})
	evResp, err := authed.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer evResp.Body.Close()
	if evResp.StatusCode != http.StatusOK {
		t.Fatalf("authed /events = %d, want 200", evResp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/api/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "xiezhi_session", Value: token})
	outResp, err := authed.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	outResp.Body.Close()
	if outResp.StatusCode != http.StatusOK {
		t.Fatalf("logout = %d, want 200", outResp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/console", nil)
	req.AddCookie(&http.Cookie{Name: "xiezhi_session", Value: token})
	afterResp, err := authed.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	afterResp.Body.Close()
	if afterResp.StatusCode != http.StatusSeeOther || afterResp.Header.Get("Location") != "/login" {
		t.Fatalf("post-logout /console = %d %q, want 303 /login", afterResp.StatusCode, afterResp.Header.Get("Location"))
	}
}

// F-001 防线：精确断言「单引号+裸换行+');'」事故模式（R8.4 审计实证：
// python 写入把 join 的 \n 参数变成真实换行，整页 JS SyntaxError 而
// HTML grep 漏网）。通用 JS 语法校验属 node --check 的职责，此守卫只锁
// 已知事故类，零误报。
func TestConsolePageScriptNoBareNewlineInString(t *testing.T) {
	page, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Skip("static page not found (embed layout changed?)")
	}
	if strings.Contains(string(page), "'\n');") {
		t.Error("script 段含 裸换行字符串+'); 事故模式（join/push 串被截断）")
	}
}
