// SPDX-License-Identifier: Apache-2.0

package intent

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

// HTTPLabeler 调外部标注服务（SecEBL sidecar）：POST {base}/label，
// 请求 {"cmdline":"..."}，响应 {"labels":[{"tag":"...","score":0.9}]}。
// 任何失败（网络/超时/非 2xx/解码错误）都返回空标签并计数——标签层旁路
// 语义：标注不可用时意图层静默退化为无信号，不报错不阻塞。
type HTTPLabeler struct {
	base   string
	client *http.Client
	fails  atomic.Uint64
}

func NewHTTPLabeler(baseURL string, timeout time.Duration) *HTTPLabeler {
	return &HTTPLabeler{
		base:   baseURL,
		client: &http.Client{Timeout: timeout},
	}
}

// Fails 暴露失败计数（Stats 汇总用）。
func (l *HTTPLabeler) Fails() uint64 { return l.fails.Load() }

type labelRequest struct {
	Cmdline string `json:"cmdline"`
}

type labelResponse struct {
	Labels []Label `json:"labels"`
}

func (l *HTTPLabeler) Label(ctx context.Context, cmdline string) []Label {
	body, err := json.Marshal(labelRequest{Cmdline: cmdline})
	if err != nil {
		l.fails.Add(1)
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.base+"/label", bytes.NewReader(body))
	if err != nil {
		l.fails.Add(1)
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.client.Do(req)
	if err != nil {
		l.fails.Add(1)
		slog.Debug("intent: http 标注失败，旁路", "err", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		l.fails.Add(1)
		slog.Debug("intent: http 标注非 2xx，旁路", "status", resp.StatusCode)
		return nil
	}
	var out labelResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		l.fails.Add(1)
		slog.Debug("intent: http 标注响应解码失败，旁路", "err", err)
		return nil
	}
	return out.Labels
}

var _ Labeler = (*HTTPLabeler)(nil)
