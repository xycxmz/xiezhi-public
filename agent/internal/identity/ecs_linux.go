// SPDX-License-Identifier: Apache-2.0

//go:build linux

package identity

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// ecsInstanceID 从阿里云 ECS metadata 取 instance-id（M3：deadman 电源对账映射键）。
// 物理机/非 ECS/超时一律返回空串（1s 超时，metadata 服务只在 ECS 上存在）。
// IMDS v1 直取；ECS 开了强制 token 模式（少见）时拿不到，心跳 instance_id
// 留空、deadman 落 not_found 告警侧，不误抑制。
func ecsInstanceID() string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://100.100.100.200/latest/meta-data/instance-id", nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	buf := make([]byte, 128)
	n, _ := resp.Body.Read(buf)
	s := strings.TrimSpace(string(buf[:n]))
	if len(s) == 0 || len(s) > 64 || !strings.HasPrefix(s, "i-") {
		return ""
	}
	return s
}
