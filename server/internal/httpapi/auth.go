// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AuthMiddleware 保护全部 HTTP 端点（除 /login 与 /healthz）。
// 会话=内存 token + cookie（xiezhi_session），24h 过期；暴力刹车=IP 5 次失败锁 15 分钟。
// 密码经 env XIEZHI_CONSOLE_PASSWORD 配置；空密码=鉴权旁路（开发模式，大声说）。

const (
	sessionCookie = "xiezhi_session"
	sessionTTL    = 24 * time.Hour
	maxLoginFails = 5
	lockoutDur    = 15 * time.Minute
)

type AuthManager struct {
	mu       sync.RWMutex
	sessions map[string]time.Time // token -> expiry
	fails    map[string]*failInfo // ip -> fail state
	password string
}

type failInfo struct {
	count    int
	lockedAt time.Time
	lastAt   time.Time // 最近一次失败时刻：未达锁定阈值条目的淘汰判据
}

func NewAuthManager(password string) *AuthManager {
	return &AuthManager{
		sessions: make(map[string]time.Time),
		fails:    make(map[string]*failInfo),
		password: password,
	}
}

// Middleware 返回 http.Handler 包装。password 为空时鉴权旁路（dev 模式）。
func (a *AuthManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 公开端点
		path := r.URL.Path
		if path == "/login" || path == "/healthz" || strings.HasPrefix(path, "/api/auth") {
			next.ServeHTTP(w, r)
			return
		}

		if a.password == "" {
			// dev 模式：无密码，全部放行（部署时必须设 XIEZHI_CONSOLE_PASSWORD）
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(sessionCookie)
		if err != nil || !a.validSession(cookie.Value) {
			// 未鉴权：HTML 页面重定向到登录，API 返回 401
			if strings.HasPrefix(path, "/api") || path == "/events" || path == "/alerts" || path == "/triage" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

// HandleLogin 处理 GET /login（登录页）与 POST /api/auth/login（登录提交）。
func (a *AuthManager) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/api/auth/login" {
		a.handleLoginAPI(w, r)
		return
	}
	// GET /login：内联登录页（克制风格，与 console 同色系）
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(loginPageHTML))
}

func (a *AuthManager) handleLoginAPI(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)

	// 暴力刹车（count/lockedAt 的读全部在锁内：与失败路径的锁内写并发）
	a.mu.RLock()
	fi, hasFI := a.fails[ip]
	locked := hasFI && fi.count >= maxLoginFails && time.Since(fi.lockedAt) < lockoutDur
	a.mu.RUnlock()
	if locked {
		http.Error(w, `{"error":"locked"}`, http.StatusTooManyRequests)
		return
	}

	password := r.FormValue("password")
	if password == "" {
		// 也接受 JSON body
		password = r.Header.Get("X-Xiezhi-Password")
	}

	// 常数时间比较
	var match int
	if subtle.ConstantTimeCompare([]byte(password), []byte(a.password)) == 1 {
		match = 1
	}

	if match != 1 {
		a.mu.Lock()
		// 锁内重查：读锁与写锁之间该条目可能被并发成功登录/Cleanup 删除，
		// 沿用锁外读到的旧指针会把计数写到已脱离 map 的对象上而丢失。
		fi = a.fails[ip]
		if fi == nil {
			fi = &failInfo{}
			a.fails[ip] = fi
		}
		fi.count++
		fi.lastAt = time.Now()
		if fi.count >= maxLoginFails {
			fi.lockedAt = time.Now()
		}
		a.mu.Unlock()
		http.Error(w, `{"error":"invalid password"}`, http.StatusUnauthorized)
		return
	}

	// 登录成功：清失败计数，发 session token
	a.mu.Lock()
	delete(a.fails, ip)
	token := a.newSessionLocked()
	a.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

// HandleLogout 处理 POST /api/auth/logout。
func (a *AuthManager) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, cookie.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookie,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func (a *AuthManager) validSession(token string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	expiry, ok := a.sessions[token]
	if !ok || time.Now().After(expiry) {
		return false
	}
	return true
}

func (a *AuthManager) newSessionLocked() string {
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)
	a.sessions[token] = time.Now().Add(sessionTTL)
	return token
}

// cleanup 定期清除过期 session（main 起 goroutine 调用）。
func (a *AuthManager) Cleanup() {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for t, exp := range a.sessions {
		if now.After(exp) {
			delete(a.sessions, t)
		}
	}
	for ip, fi := range a.fails {
		if fi.count >= maxLoginFails && now.Sub(fi.lockedAt) > lockoutDur {
			delete(a.fails, ip)
			continue
		}
		// 未达锁定阈值的条目也要淘汰：公网扫描源每个唯一 IP 只失败 1-4 次
		// 即可让 fails map 无界增长。
		if fi.count < maxLoginFails && now.Sub(fi.lastAt) > lockoutDur {
			delete(a.fails, ip)
		}
	}
}

func clientIP(r *http.Request) string {
	// 只信任 RemoteAddr（X-Forwarded-For 可伪造）
	idx := strings.LastIndex(r.RemoteAddr, ":")
	if idx > 0 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

const loginPageHTML = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>xiezhi-console login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{border:1px solid #e5e5e5;padding:40px;width:320px}
h1{font-size:16px;font-weight:600;color:#111;margin-bottom:24px}
input{width:100%;padding:8px 12px;border:1px solid #e5e5e5;font-family:monospace;font-size:14px;margin-bottom:16px;border-radius:0}
input:focus{outline:none;border-color:#111}
button{width:100%;padding:8px;background:#111;color:#fff;border:none;font-size:14px;cursor:pointer;border-radius:0}
button:hover{background:#333}
.err{color:#dc2626;font-size:12px;margin-top:8px;font-family:monospace}
</style></head><body>
<div class="card">
<h1>xiezhi-console</h1>
<form onsubmit="login(event)">
<input type="password" id="pw" placeholder="password" autofocus autocomplete="current-password">
<button type="submit">Login</button>
<div class="err" id="err"></div>
</form>
</div>
<script>
async function login(e){
e.preventDefault();
const pw=document.getElementById('pw').value;
const err=document.getElementById('err');
try{
const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'password='+encodeURIComponent(pw)});
if(r.ok){location.href='/console'}
else if(r.status===429){err.textContent='locked, wait 15 min'}
else{err.textContent='invalid password'}
}catch(x){err.textContent='network error'}
}
</script></body></html>`
