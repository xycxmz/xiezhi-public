// SPDX-License-Identifier: Apache-2.0

// Package sdnotify 实现 systemd Type=notify 协议（READY=1 与 WATCHDOG=1）。
// NOTIFY_SOCKET 不存在（手工运行/非 systemd/Windows）时全部为无操作。
package sdnotify

import (
	"net"
	"os"
	"time"
)

func send(socket, state string) {
	conn, err := net.Dial("unixgram", socket)
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("STATUS=" + state))
}

// Ready 通知 systemd 服务就绪（Type=notify 的启动闸门）。
func Ready() {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return
	}
	if conn, err := net.Dial("unixgram", socket); err == nil {
		_, _ = conn.Write([]byte("READY=1"))
		conn.Close()
	}
}

// Watchdog 按 WATCHDOG_USEC 的一半周期持续喂狗，返回停止函数。
// agent 主循环卡死时由 systemd 强制重启（卡死不退出的自愈）。
func Watchdog() (stop func()) {
	socket := os.Getenv("NOTIFY_SOCKET")
	usec := os.Getenv("WATCHDOG_USEC")
	if socket == "" || usec == "" {
		return func() {}
	}
	d, err := time.ParseDuration(usec + "us")
	if err != nil || d <= 0 {
		return func() {}
	}
	ticker := time.NewTicker(d / 2)
	done := make(chan struct{})
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if conn, err := net.Dial("unixgram", socket); err == nil {
					_, _ = conn.Write([]byte("WATCHDOG=1"))
					conn.Close()
				}
			}
		}
	}()
	var once bool
	return func() {
		if !once {
			once = true
			close(done)
		}
	}
}
