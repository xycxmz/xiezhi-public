// SPDX-License-Identifier: Apache-2.0

package httpapi

import "net/http"

// AuthMiddleware 是鉴权中间件接口（httpapi 包对 auth 实现的依赖边界）。
type AuthMiddleware interface {
	Wrap(next http.Handler) http.Handler
}

// Wrap 包装 mux，保护全部端点。
func (a *AuthManager) Wrap(next http.Handler) http.Handler {
	return a.Middleware(next)
}
