// SPDX-License-Identifier: Apache-2.0

package deadman

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestRealSASProbe 直连真 SAS 定位 reconcile_unavailable（env 门控，不进 CI）。
// 运行：XIEZHI_SAS_PROBE=1 XIEZHI_SAS_AK=.. XIEZHI_SAS_SK=.. go test -run RealSAS -v
func TestRealSASProbe(t *testing.T) {
	if os.Getenv("XIEZHI_SAS_PROBE") != "1" {
		t.Skip("env-gated real-endpoint probe")
	}
	c := newSASClient(os.Getenv("XIEZHI_SAS_AK"), os.Getenv("XIEZHI_SAS_SK"),
		"sas.cn-shanghai.aliyuncs.com")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	insts, err := c.fetchAll(ctx)
	if err != nil {
		t.Fatalf("fetchAll: %v", err)
	}
	t.Logf("instances=%d", len(insts))
	if len(insts) == 0 {
		t.Fatal("empty result")
	}
}
