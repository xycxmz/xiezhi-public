// SPDX-License-Identifier: Apache-2.0

// Package runtime 是 agent 运行时：驱动注册的采集器、统一富化事件
// 公共头（seq 单调的唯一种源）、产生心跳，并按注册序收尾采集器。
package runtime

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/xycxmz/xiezhi-public/proto"

	"github.com/xycxmz/xiezhi-public/agent/internal/collector"
	"github.com/xycxmz/xiezhi-public/agent/internal/config"
	"github.com/xycxmz/xiezhi-public/agent/internal/identity"
)

// Sink 是 runtime 对 forwarder 的最小依赖面（独立测试用假件实现）。
type Sink interface {
	In() chan *pb.Event
	SpoolBytes() uint64
}

type Runtime struct {
	cfg        *config.Config
	id         *identity.Identity
	sink       Sink
	version    string
	collectors []collector.Collector

	seq       atomic.Uint64
	seqMu     sync.Mutex    // saveSeq 串行化：并发 enrich 的水位写不互踩 tmp 文件
	submitted atomic.Uint64 // 成功入队 forwarder 的事件数（心跳 events_sent）
	dropped   atomic.Uint64 // 入口满被丢弃的事件数（心跳 events_dropped）

	// heartbeatTick 默认取 cfg.HeartbeatIntervalSec；包内测试可改小。
	heartbeatTick time.Duration
}

func New(cfg *config.Config, id *identity.Identity, sink Sink, version string, collectors ...collector.Collector) *Runtime {
	return &Runtime{
		cfg:           cfg,
		id:            id,
		sink:          sink,
		version:       version,
		collectors:    collectors,
		heartbeatTick: time.Duration(cfg.HeartbeatIntervalSec) * time.Second,
	}
}

// Run 阻塞运行。ctx 取消后：等各采集器 Run 返回，按注册序 Close，
// 再返回。事件投递全程非阻塞（select-default），采集器永不被入口反压。
func (r *Runtime) Run(ctx context.Context) error {
	r.loadSeq()
	// 闭包 defer：直接 defer r.saveSeq(r.seq.Load()) 会在 defer 语句处求值，
	// 停机落盘的是启动快照并覆盖周期检查点（修复者复核发现）。
	defer func() { r.saveSeq(r.seq.Load()) }()

	rctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var runWG, pumpWG sync.WaitGroup
	for _, c := range r.collectors {
		c := c
		runWG.Add(1)
		go func() {
			defer runWG.Done()
			if err := c.Run(rctx); err != nil {
				log.Printf("runtime: collector %s exited: %v", c.Name(), err)
			}
		}()
		pumpWG.Add(1)
		go func() {
			defer pumpWG.Done()
			for ev := range c.Events() {
				r.submit(ev)
			}
		}()
	}

	hbDone := make(chan struct{})
	go r.heartbeat(rctx, hbDone)

	<-ctx.Done()
	cancel()
	runWG.Wait()
	pumpWG.Wait()
	for _, c := range r.collectors {
		c.Close()
	}
	<-hbDone
	return nil
}

// Stats 返回心跳口径的计数：入队成功数与入口丢弃数。
func (r *Runtime) Stats() (sent, dropped uint64) {
	return r.submitted.Load(), r.dropped.Load()
}

func (r *Runtime) submit(ev *pb.Event) {
	if ev == nil {
		return
	}
	r.enrich(ev)
	select {
	case r.sink.In() <- ev:
		r.submitted.Add(1)
	default:
		r.dropped.Add(1)
	}
}

// enrich 填公共头。seq 是 agent 内全局单调唯一序（原子分配，多采集器
// 并发下取值唯一；送达顺序在并发下允许与分配顺序交错，服务端按 seq
// 对账）。event_type/cgroup_id/container_id 尊重采集器已填值。
// seq 起点=持久化水位（重启不归零）：服务端 8192 去重窗对重启重放是
// 过渡态兜底，水位文件让它彻底失效。
func (r *Runtime) enrich(ev *pb.Event) {
	if ev.Header == nil {
		ev.Header = &pb.EventHeader{}
	}
	h := ev.Header
	h.AgentId = r.id.AgentID
	h.Hostname = r.id.Hostname
	h.BootId = r.id.BootID
	h.Kernel = r.id.Kernel
	h.TsMs = uint64(time.Now().UnixMilli())
	h.Seq = r.seq.Add(1)
	if h.Seq%1024 == 0 {
		r.saveSeq(h.Seq)
	}
}

// loadSeq 启动时从水位文件恢复 seq（文件在 cfg.SpoolDir/../seq，容错缺失）。
func (r *Runtime) loadSeq() {
	path := r.seqPath()
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || v == 0 {
		return
	}
	// +1M 安全垫：水位可能落后于最后落盘事件（每 1024 才存）
	r.seq.Store(v + 1_000_000)
}

// saveSeq 水位落盘：临时文件 + rename 原子替换（参照 identity.go 的
// agent_id 持久化）。直写在掉电时可能留下截断/空文件，loadSeq 会静默
// 归零导致整段重放（R8.4 审计 A-4）。上次崩溃残留的 tmp 由 WriteFile
// 直接截断覆盖（容忍），失败保持旧水位不回退。
func (r *Runtime) saveSeq(v uint64) {
	r.seqMu.Lock()
	defer r.seqMu.Unlock()
	path := r.seqPath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatUint(v, 10)), 0o600); err != nil {
		return
	}
	// Windows 上 rename 不覆盖已存在文件；先移除旧水位再换名（identity.go 同款）。
	_ = os.Remove(path)
	_ = os.Rename(tmp, path)
}

func (r *Runtime) seqPath() string {
	return filepath.Join(filepath.Dir(r.cfg.SpoolDir), "seq")
}

func (r *Runtime) heartbeat(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	if r.heartbeatTick <= 0 {
		return
	}
	t := time.NewTicker(r.heartbeatTick)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			r.submit(&pb.Event{
				Header: &pb.EventHeader{EventType: pb.EventType_AGENT_HEARTBEAT},
				Body: &pb.Event_Heartbeat{Heartbeat: &pb.HeartbeatEvent{
					AgentVersion:  r.version,
					Kernel:        r.id.Kernel,
					CollectorMode: r.collectorMode(),
					// driver_loaded 置位需要 eBPF collector 上报加载状态（M1-A 后接入）。
					EventsSent:    r.submitted.Load(),
					EventsDropped: r.dropped.Load(),
					SpoolBytes:    r.sink.SpoolBytes(),
					InstanceId:    r.id.InstanceID,
				}}})
		case <-ctx.Done():
			return
		}
	}
}

func (r *Runtime) collectorMode() string {
	if len(r.collectors) == 0 {
		return "none"
	}
	names := make([]string, 0, len(r.collectors))
	for _, c := range r.collectors {
		names = append(names, c.Name())
	}
	return strings.Join(names, ",")
}
