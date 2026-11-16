// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lkm

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

func newPipeCollector(f *os.File) *Collector {
	c := &Collector{
		events: make(chan *pb.Event, 16),
		log:    testLogger(),
	}
	c.openData = func() (*os.File, error) { return f, nil }
	c.ensureLoaded = func(context.Context) (time.Duration, error) { return 0, nil }
	return c
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

// 端到端：管道当 /proc 数据面（poll 对管道同样有效），含一颗坏帧，
// Run 须解码投递三种事件并在 ctx 取消后关闭通道。
func TestRunEmitsEventsAndClosesChannel(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	c := newPipeCollector(pr)

	bad := make([]byte, 4) // total=0 坏帧
	stream := append(append(append(append([]byte{}, frameOf(t, testExecEv())...), bad...), frameOf(t, testConnEv())...), frameOf(t, testDns6Ev())...)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	if _, err := pw.Write(stream); err != nil {
		t.Fatal(err)
	}

	ev1 := recvEvent(t, c.events)
	if ev1.Header.EventType != pb.EventType_EXECVE || ev1.GetExecve().Proc.Exe != "/usr/bin/curl" {
		t.Errorf("event 1 = %v, want EXECVE of /usr/bin/curl", ev1.Header.EventType)
	}
	ev2 := recvEvent(t, c.events)
	if ev2.Header.EventType != pb.EventType_CONNECT || ev2.GetNet().Port != 443 {
		t.Errorf("event 2 = %v, want CONNECT port 443", ev2.Header.EventType)
	}
	ev3 := recvEvent(t, c.events)
	if ev3.Header.EventType != pb.EventType_DNS_QUERY || ev3.GetDns().ServerIp != "2001:db8::1" {
		t.Errorf("event 3 = %v, want DNS_QUERY to 2001:db8::1", ev3.Header.EventType)
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
	pw.Close()
}

// 驱动持续加载失败：Run 阻塞在退避等待，不热转，ctx 取消后干净退出。
func TestRunLoadFailureBacksOffUntilCancel(t *testing.T) {
	c := &Collector{
		events: make(chan *pb.Event, 16),
		log:    testLogger(),
	}
	c.openData = func() (*os.File, error) { return nil, errors.New("unreachable") }
	c.ensureLoaded = func(context.Context) (time.Duration, error) {
		return time.Hour, errors.New("ko vanished")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return during backoff sleep after ctx cancel")
	}
	if ev, ok := <-c.events; ok {
		t.Errorf("channel has event %v, want closed and empty", ev)
	}
}

// New 在 ko 目录无当前内核匹配时须给出明确错误（主会话据此降级心跳模式）。
func TestNewWithoutKo(t *testing.T) {
	_, err := New(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "no driver") {
		t.Errorf("New err = %v, want explicit no-driver error", err)
	}
}
