// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	goruntime "runtime"
	"syscall"
	"time"

	"github.com/xycxmz/xiezhi-public/agent/internal/collector"
	"github.com/xycxmz/xiezhi-public/agent/internal/collector/ebpf"
	"github.com/xycxmz/xiezhi-public/agent/internal/collector/journal"
	"github.com/xycxmz/xiezhi-public/agent/internal/collector/lkm"
	"github.com/xycxmz/xiezhi-public/agent/internal/collector/procpoll"
	"github.com/xycxmz/xiezhi-public/agent/internal/config"
	"github.com/xycxmz/xiezhi-public/agent/internal/forwarder"
	"github.com/xycxmz/xiezhi-public/agent/internal/identity"
	"github.com/xycxmz/xiezhi-public/agent/internal/runtime"
	"github.com/xycxmz/xiezhi-public/agent/internal/sdnotify"
)

var buildVersion = "0.0.1"

func main() {
	cfgPath := flag.String("c", "", "config file path (env XIEZHI_AGENT_CONFIG, default /etc/xiezhi-agent/config.yaml)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("xiezhi-agent %s %s/%s\n", buildVersion, goruntime.GOOS, goruntime.GOARCH)
		return
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg, err := config.Load(config.Path(*cfgPath))
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if cfg.ServerAddr == "" {
		log.Fatalf("config: server_addr is required")
	}
	if cfg.Token == "" {
		log.Fatalf("config: token is required")
	}

	id, err := identity.Load(cfg.AgentIDFile)
	if err != nil {
		log.Fatalf("identity: %v", err)
	}

	sender := forwarder.NewGRPCSender(cfg.ServerAddr, cfg.Token, cfg.TLSCa, cfg.TLSCert, cfg.TLSKey)
	defer sender.Close()
	fwd, err := forwarder.New(&cfg, sender)
	if err != nil {
		log.Fatalf("forwarder: %v", err)
	}

	collectors := []collector.Collector{}
	if c, err := ebpf.New(); err != nil {
		// 心跳/通道在无采集器时仍有价值（dead-man 不死），采集面缺失要大声说
		log.Printf("ebpf collector unavailable, trying lkm: %v", err)
	} else {
		collectors = append(collectors, c)
	}
	// LKM 线显式开关（3.10 车队主力线）；eBPF 可用且未显式开启时不重复加载
	if cfg.DriverEnabled {
		if c, err := lkm.New(cfg.DriverKoDir); err != nil {
			log.Printf("lkm collector unavailable, heartbeat-only: %v", err)
		} else {
			collectors = append(collectors, c)
		}
	}
	// /proc 对账与认证日志两通道与内核线独立，失败各自降级不互相拖
	if c, err := procpoll.New(time.Duration(cfg.ProcpollIntervalSec) * time.Second); err != nil {
		log.Printf("procpoll collector unavailable: %v", err)
	} else {
		collectors = append(collectors, c)
	}
	if c, err := journal.New(cfg.JournalPath); err != nil {
		log.Printf("journal collector unavailable: %v", err)
	} else {
		collectors = append(collectors, c)
	}

	rt := runtime.New(&cfg, id, fwd, buildVersion, collectors...)
	stopWatchdog := sdnotify.Watchdog()

	// 第二次 SIGTERM/SIGINT 走默认处理硬退出（冲刷窗口内强停）。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// forwarder 的停机 ctx 与信号解耦：runtime（含全部采集器 pump）完全
	// 停止后才触发，mux 在停机期持续消费入口，泵晚到的事件不滞留丢失、
	// events_sent 口径不失真。
	fwdCtx, fwdCancel := context.WithCancel(context.Background())
	defer fwdCancel()
	go fwd.Run(fwdCtx)
	sdnotify.Ready()
	if err := rt.Run(ctx); err != nil {
		log.Printf("runtime: %v", err)
	}
	stop()      // 恢复默认信号处置：此后第二次信号即硬退出
	fwdCancel() // runtime 已全停，现在进入 forwarder 冲刷窗口
	<-fwd.Done()
	stopWatchdog()
	log.Printf("xiezhi-agent %s stopped (agent_id=%s)", buildVersion, id.AgentID)
}
