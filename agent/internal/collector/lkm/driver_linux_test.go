// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lkm

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestKoPathFor(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "xiezhi_driver-3.10.0-1160.el7.x86_64.ko")
	for _, name := range []string{
		target,
		filepath.Join(dir, "xiezhi_driver-3.10.0-862.3.3.el7.x86_64.ko"),
		filepath.Join(dir, "xiezhi_driver-3.10.0-1160.el7.x86_64.ko.txt"),
		filepath.Join(dir, "random.txt"),
	} {
		if err := os.WriteFile(name, []byte{}, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name       string
		dir        string
		release    string
		wantPath   string
		wantErrSub string
	}{
		{"exact match", dir, "3.10.0-1160.el7.x86_64", target, ""},
		{"version mismatch", dir, "3.10.0-999.el7.x86_64", "", "no driver"},
		{"suffix decoy ignored", dir, "3.10.0-1160.el7.x86_64.ko", "", "no driver"},
		{"empty dir", t.TempDir(), "3.10.0-1160.el7.x86_64", "", "no driver"},
		{"dir not configured", "", "3.10.0-1160.el7.x86_64", "", "not configured"},
	} {
		got, err := koPathFor(tc.dir, tc.release)
		if tc.wantErrSub != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("%s: err = %v, want containing %q", tc.name, err, tc.wantErrSub)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected err %v", tc.name, err)
			continue
		}
		if got != tc.wantPath {
			t.Errorf("%s: path = %q, want %q", tc.name, got, tc.wantPath)
		}
	}
}

func TestNewManager(t *testing.T) {
	if _, err := newManager("", "3.10.0-1160.el7.x86_64", testLogger()); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Errorf("empty dir: err = %v, want not configured", err)
	}
	if _, err := newManager(t.TempDir(), "9.9.9-fake", testLogger()); err == nil || !strings.Contains(err.Error(), "no driver") {
		t.Errorf("missing ko: err = %v, want no driver", err)
	}
	dir := t.TempDir()
	rel := "3.10.0-1160.el7.x86_64"
	ko := filepath.Join(dir, "xiezhi_driver-"+rel+".ko")
	if err := os.WriteFile(ko, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := newManager(dir, rel, testLogger())
	if err != nil {
		t.Fatalf("unexpected err %v", err)
	}
	if m.koPath != ko || m.attempts != 0 || m.loaded {
		t.Errorf("manager state = %+v", m)
	}
}

func TestBackoffDelay(t *testing.T) {
	for _, tc := range []struct {
		failures int
		want     time.Duration
	}{
		{-5, time.Second},
		{0, time.Second},
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{3, 8 * time.Second},
		{10, 1024 * time.Second},
		{11, 2048 * time.Second},
		{12, 3600 * time.Second},
		{13, 3600 * time.Second},
		{100, 3600 * time.Second},
	} {
		if got := backoffDelay(tc.failures); got != tc.want {
			t.Errorf("backoffDelay(%d) = %v, want %v", tc.failures, got, tc.want)
		}
	}
}

func TestModuleLoadedIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want bool
	}{
		{"present", "xiezhi_driver 24576 0 - Live 0xffffffffc06a0000 (OE)\n", true},
		{"first of many", "xiezhi_driver 24576 0 - Live 0x...\nnvme 40960 5 - Live 0x...\n", true},
		{"other modules only", "nvme 40960 5 - Live 0x...\ncfg80211 983042 0 - Live 0x...\n", false},
		{"prefix decoy", "xiezhi_driverx 1 1 - Live 0x...\n", false},
		{"empty", "", false},
	} {
		if got := moduleLoadedIn(tc.text); got != tc.want {
			t.Errorf("%s: moduleLoadedIn = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRecentXiezhiCrash(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)
	now := boot.Add(24 * time.Hour) // uptime 基准 86400s
	for _, tc := range []struct {
		name string
		line string
		want bool
	}{
		{"recent oops implicating xiezhi", "[86340.123456] xiezhi_driver: Oops: 0000 [#1] SMP", true},
		{"recent RIP with xiezhi symbol", "[86341.000000] RIP: 0010:[<ffffffffc06a0012>] xiezhi_execve+0x12/0x40", true},
		{"recent BUG implicating xiezhi", "[86342.000000] BUG: unable to handle kernel paging request at xiezhi_ring_put+0x2a", true},
		{"recent panic implicating xiezhi", "[86343.000000] Kernel panic - not syncing: xiezhi driver corrupted state", true},
		{"old oops outside window", "[85800.000000] xiezhi_driver: Oops: 0000", false},
		{"recent crash without xiezhi", "[86340.500000] some_mod: Oops: 0000", false},
		{"benign xiezhi log line", "[86344.000000] xiezhi: driver up (/proc/xiezhi/endpoint)", false},
		{"no uptime stamp", "xiezhi Oops: kernel oops in xiezhi module", false},
	} {
		if got := recentXiezhiCrash(tc.line, boot, now); got != tc.want {
			t.Errorf("%s: recentXiezhiCrash = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A-2：真实 oops 多行分列形态（标记行不含模块名）必须命中；无关崩溃不命中。
func TestRecentCrashMultiLineOops(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)
	now := boot.Add(30 * time.Minute)
	// 夹具时间戳必须落在 crashWindow 内：now=boot+30min，cutoff=uptime 1500s。
	multi := "[ 1790.5] CPU: 3 PID: 1 Comm: systemd\n" +
		"[ 1790.5] Hardware name\n" +
		"[ 1790.6] Oops: 0000 [#1] SMP\n" +
		"[ 1790.6] RIP: 0010:list_lru_del+0x1c/0x90\n" +
		"[ 1790.7] Call Trace:\n" +
		"[ 1790.7]  xiezhi_inode_free+0x2a [xiezhi_driver]\n"
	if !recentXiezhiCrash(multi, boot, now) {
		t.Error("multi-line oops with xiezhi in call trace must be detected")
	}
	// 负例：oops 在窗口外（746s < cutoff 1500s）被时间过滤，xiezhi 行在窗口内
	// 但邻近无标记行——检测不得命中。
	unrelated := "[ 746.5] Oops: 0000 [#1] SMP\n" +
		"[ 746.6] RIP: 0010:ext4_delete_io\n" +
		"[ 1795.0] xiezhi: driver up (/proc/xiezhi/endpoint)\n"
	if recentXiezhiCrash(unrelated, boot, now) {
		t.Error("unrelated oops far from xiezhi lines must not be detected")
	}
}
