// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procpoll

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeStat 生成一条 /proc/<pid>/stat：comm（字段 2）在括号里，其后从字段 3
// （state）起，starttime（字段 22）落在下标 19（itrealvalue=字段 21 是它前一个）。
func fakeStat(pid int, comm string, startTicks string) string {
	post := []string{
		"S", "1", "1", "1", "0", "-1", "4194560",
		"12345", "0", "0", "0", "5", "3", "0", "0", "0", "20", "0", "0",
		startTicks, "123456", "256", "0", "0", "0", "0", "0",
	}
	return itoa(pid) + " (" + comm + ") " + strings.Join(post, " ") + "\n"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func writeFakeProc(t *testing.T, root string, pid int, comm string, ticks string, withExe bool) {
	t.Helper()
	dir := filepath.Join(root, itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	status := "Name:\t" + comm + "\nUmask:\t0022\nState:\tS (sleeping)\nPPid:\t1\n"
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(fakeStat(pid, comm, ticks)), 0o644); err != nil {
		t.Fatal(err)
	}
	if withExe {
		if err := os.Symlink("/usr/bin/fake", filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
}

// 假目录树当 /proc：正常项、内核线程（无 exe）、comm 含空格括号、非 pid
// 目录名、非目录项、缺 status/stat 的残项。
func TestScanFakeProcTree(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, 1, "systemd", "100", true)
	writeFakeProc(t, root, 42, "kworker/0:1", "200", false)
	writeFakeProc(t, root, 999, "taku (dead)", "300", true)

	if err := os.MkdirAll(filepath.Join(root, "acpi"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "123file"), []byte("not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 残项：扫到一半退出的进程形态——只建目录和 status
	broken := filepath.Join(root, "777")
	if err := os.MkdirAll(broken, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, "status"), []byte("Name:\tzombie\nPPid:\t1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	snap := scan(root)
	if len(snap) != 3 {
		t.Fatalf("snapshot size = %d (%v), want 3 (broken and non-pid entries skipped)", len(snap), snap)
	}
	e := snap[999]
	if e.Comm != "taku (dead)" || e.StartTicks != 300 || e.Exe != "/usr/bin/fake" || e.Ppid != 1 {
		t.Errorf("entry 999 = %+v, want comm=taku (dead) ticks=300 exe=/usr/bin/fake ppid=1", e)
	}
	if k := snap[42]; k.Exe != "" {
		t.Errorf("kernel-thread style entry 42 exe = %q, want empty", k.Exe)
	}
}

// stat 的 comm 含 ')' 时按下标 19 取 starttime 仍须正确（LastIndexByte 切分）。
func TestScanCommWithParens(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "7")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	status := "Name:\t(tainted)\nPPid:\t3\n"
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	statLine := "7 ((ta)int)ed)) S 3 7 7 0 -1 4194560 1 0 0 0 1 1 0 0 0 20 0 0 55555 999 1 0 0 0 0 0\n"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(statLine), 0o644); err != nil {
		t.Fatal(err)
	}
	snap := scan(root)
	e, ok := snap[7]
	if !ok {
		t.Fatalf("pid 7 missing from snapshot: %v", snap)
	}
	if e.StartTicks != 55555 {
		t.Errorf("StartTicks = %d, want 55555 (field 22 behind comm with parens)", e.StartTicks)
	}
}

// 残缺 stat（token 不足 20）必须整条跳过，不能以 ticks=0 进快照。
func TestScanMalformedStatSkipped(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "9")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte("Name:\tx\nPPid:\t1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte("9 (x) S 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if snap := scan(root); len(snap) != 0 {
		t.Errorf("snapshot = %v, want empty for malformed stat", snap)
	}
}
