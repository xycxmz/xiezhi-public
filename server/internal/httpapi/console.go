// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"embed"
	"net/http"
)

//go:embed static/index.html
var consoleFS embed.FS

var consoleHTML = func() []byte {
	b, _ := consoleFS.ReadFile("static/index.html")
	return b
}()

// registerConsole 挂 GET /console（嵌入的六 tab 单页控制台）与
// GET / （303 → /console，未鉴权时由中间件再转到 /login）。
// 同一 mux 只能注册一次（ServeMux 重复 pattern 会 panic）；
// 由 NewWithAuth 装配调用。
func registerConsole(mux *http.ServeMux) {
	if mux == nil || len(consoleHTML) == 0 {
		return
	}
	mux.HandleFunc("GET /console", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(consoleHTML)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/console", http.StatusSeeOther)
	})
}
