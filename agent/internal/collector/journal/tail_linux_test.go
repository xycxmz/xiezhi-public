// SPDX-License-Identifier: Apache-2.0

//go:build linux

package journal

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
}

// 初始定位：150 行文件只吐最后 100 行（tail -N 语义），后续 poll 只吐增量。
func TestTailStartLinesAndIncremental(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	var b []byte
	for i := 0; i < 150; i++ {
		b = append(b, []byte(fmt.Sprintf("L%03d\n", i))...)
	}
	mustWrite(t, path, string(b))

	tl := newTailer(path, 100)
	lines := tl.pollAll(t)
	if len(lines) != 100 {
		t.Fatalf("initial batch = %d lines, want 100", len(lines))
	}
	if lines[0] != "L050" || lines[99] != "L149" {
		t.Errorf("initial batch bounds = [%s, %s], want [L050, L149]", lines[0], lines[99])
	}

	mustWrite(t, path, "L150\nL151\n")
	lines = tl.pollAll(t)
	if len(lines) != 2 || lines[0] != "L150" || lines[1] != "L151" {
		t.Errorf("incremental batch = %v, want [L150 L151]", lines)
	}

	if lines = tl.pollAll(t); len(lines) != 0 {
		t.Errorf("idle poll = %v, want empty", lines)
	}
}

// 半行跨 poll：无换行不吐，换行到齐后吐完整行。
func TestTailPartialLineHeld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	mustWrite(t, path, "first\nhalf-a-li")
	tl := newTailer(path, 10)

	if lines := tl.pollAll(t); len(lines) != 1 || lines[0] != "first" {
		t.Fatalf("first poll = %v, want [first]", lines)
	}
	mustWrite(t, path, "ne\n")
	lines := tl.pollAll(t)
	if len(lines) != 1 || lines[0] != "half-a-line" {
		t.Fatalf("second poll = %v, want [half-a-line]", lines)
	}
}

// 轮转（rename+create，新 inode）：从 0 读新文件。
func TestTailRotationNewInode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	mustWrite(t, path, "old-1\nold-2\n")
	tl := newTailer(path, 10)
	if lines := tl.pollAll(t); len(lines) != 2 {
		t.Fatalf("initial = %v, want 2 lines", lines)
	}

	fresh := filepath.Join(dir, "auth.log.new")
	mustWrite(t, fresh, "new-1\nnew-2\n")
	if err := os.Rename(fresh, path); err != nil {
		t.Fatal(err)
	}

	lines := tl.pollAll(t)
	if len(lines) != 2 || lines[0] != "new-1" || lines[1] != "new-2" {
		t.Fatalf("post-rotation = %v, want [new-1 new-2] read from offset 0", lines)
	}
}

// copytruncate（同 inode 截短重写）：offset 回退检测后从 0 重读。
func TestTailTruncateSameInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	mustWrite(t, path, "aaa\nbbb\nccc\nddd\neee\n")
	tl := newTailer(path, 10)
	if lines := tl.pollAll(t); len(lines) != 5 {
		t.Fatalf("initial = %d lines, want 5", len(lines))
	}

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, path, "xxx\nyyy\n")

	lines := tl.pollAll(t)
	if len(lines) != 2 || lines[0] != "xxx" || lines[1] != "yyy" {
		t.Fatalf("post-truncate = %v, want [xxx yyy] reread from 0", lines)
	}
}

// 轮转间隙（路径消失）：poll 不报错，下轮文件回来后正常续读。
func TestTailPathVanishesTemporarily(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	mustWrite(t, path, "a\n")
	tl := newTailer(path, 10)
	if lines := tl.pollAll(t); len(lines) != 1 {
		t.Fatalf("initial = %v, want [a]", lines)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if lines, err := tl.poll(); err != nil || len(lines) != 0 {
		t.Fatalf("poll on vanished path = (%v, %v), want empty batch and no error", lines, err)
	}

	fresh := filepath.Join(dir, "auth.log.next")
	mustWrite(t, fresh, "b\n")
	if err := os.Rename(fresh, path); err != nil {
		t.Fatal(err)
	}
	lines := tl.pollAll(t)
	if len(lines) != 1 || lines[0] != "b" {
		t.Fatalf("after file returns = %v, want [b]", lines)
	}
}

// 路径消失后替换文件在间隙期已写超 startWindow（64KB）：重开须与 inode 轮转
// 路径一致从 0 读，不得走首启的 tail -N 定位跳过窗口外的前段行。
func TestTailReopenAfterVanishReadsFromStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	mustWrite(t, path, "seed\n")
	tl := newTailer(path, 10)
	if lines := tl.pollAll(t); len(lines) != 1 {
		t.Fatalf("initial = %v, want [seed]", lines)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if lines, err := tl.poll(); err != nil || len(lines) != 0 {
		t.Fatalf("poll on vanished path = (%v, %v), want empty batch and no error", lines, err)
	}

	// 间隙期新文件积累 >64KB（11000 行 × 8B = 88KB）
	fresh := filepath.Join(dir, "auth.log.next")
	var b []byte
	const n = 11000
	for i := 0; i < n; i++ {
		b = append(b, []byte(fmt.Sprintf("g%06d\n", i))...)
	}
	mustWrite(t, fresh, string(b))
	if err := os.Rename(fresh, path); err != nil {
		t.Fatal(err)
	}

	lines := tl.pollAll(t)
	if len(lines) != n {
		t.Fatalf("after vanish-replace got %d lines, want %d (read from 0, not tail -N window)", len(lines), n)
	}
	if lines[0] != "g000000" || lines[n-1] != fmt.Sprintf("g%06d", n-1) {
		t.Fatalf("bounds = [%s, %s], want [g000000, g%06d]", lines[0], lines[n-1], n-1)
	}
}

// poll 瞬时故障（路径被目录顶替 → ReadAll EISDIR）不得终止通道：
// 记日志持续重试，故障消除后恢复投递（回归：首个 poll 错误曾让 Run 永久退出）。
func TestRunSurvivesPollErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	mustWrite(t, path, "Nov 12 10:00:01 web01 sshd[1]: Accepted password for alice from 10.0.0.5 port 51000 ssh2\n")

	c := newTestCollector(path)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	ev1 := recvEvent(t, c.events)
	if a := ev1.GetJournalAuth(); a.Kind != "ssh_login" {
		t.Fatalf("initial event = %+v, want ssh_login", a)
	}

	// 用目录顶替日志路径：tailer 的 ReadAll 返回 EISDIR，poll 持续报错
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	select {
	case ev, ok := <-c.events:
		if ok {
			t.Fatalf("unexpected event during fault: %+v", ev)
		}
		t.Fatal("events channel closed during transient poll fault")
	case <-time.After(200 * time.Millisecond):
	}

	// 故障消除：恢复为普通文件，通道必须仍在投递
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, path, "su[9]: FAILED SU (eve) to root on /dev/pts/3\n")
	ev2 := recvEvent(t, c.events)
	if a := ev2.GetJournalAuth(); a.Kind != "su" || a.User != "eve" {
		t.Fatalf("recovered event = %+v, want su eve", a)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

func (t *tailer) pollAll(tt *testing.T) []string {
	tt.Helper()
	lines, err := t.poll()
	if err != nil {
		tt.Fatalf("poll: %v", err)
	}
	return lines
}

func newTestCollector(path string) *Collector {
	return &Collector{
		events:     make(chan *pb.Event, 64),
		log:        testLogger(),
		path:       path,
		interval:   20 * time.Millisecond,
		startLines: 10,
	}
}

func recvEvent(t *testing.T, ch <-chan *pb.Event) *pb.Event {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("events channel closed unexpectedly")
		}
		return ev
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for event")
		return nil
	}
}

// Run 端到端：初始批事件、追加事件、轮转后新文件事件、ctx 取消关通道。
func TestRunEmitsParsesAndSurvivesRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	mustWrite(t, path, "Nov 12 10:00:01 web01 sshd[1]: Accepted password for alice from 10.0.0.5 port 51000 ssh2\n")

	c := newTestCollector(path)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	ev1 := recvEvent(t, c.events)
	if ev1.Header.EventType != pb.EventType_JOURNAL_AUTH {
		t.Fatalf("event type = %v, want JOURNAL_AUTH", ev1.Header.EventType)
	}
	if a := ev1.GetJournalAuth(); a.Kind != "ssh_login" || a.User != "alice" || a.Result != "success" {
		t.Errorf("event = %+v, want ssh_login alice success", a)
	}

	mustWrite(t, path, "sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id\n")
	ev2 := recvEvent(t, c.events)
	if a := ev2.GetJournalAuth(); a.Kind != "sudo" || a.User != "bob" {
		t.Errorf("append event = %+v, want sudo bob", a)
	}

	fresh := filepath.Join(dir, "auth.log.next")
	mustWrite(t, fresh, "su[9]: FAILED SU (eve) to root on /dev/pts/3\n")
	if err := os.Rename(fresh, path); err != nil {
		t.Fatal(err)
	}
	ev3 := recvEvent(t, c.events)
	if a := ev3.GetJournalAuth(); a.Kind != "su" || a.User != "eve" || a.Result != "failed" {
		t.Errorf("post-rotation event = %+v, want su eve failed", a)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
	if _, ok := <-c.events; ok {
		t.Error("events channel not closed after Run returned")
	}
}

// New 对不存在的文件必须给明确错误（main 据此降级）。空路径默认
// /var/log/auth.log 的存在性随环境而定，不做断言。
func TestNewMissingFile(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "nope.log")); err == nil {
		t.Error("New on missing file: err = nil, want explicit error")
	}
}
