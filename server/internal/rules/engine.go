// SPDX-License-Identifier: Apache-2.0

// Package rules 实现字段规则引擎：加载 YAML 规则（1s 轮询热更）、按冻结的
// protojson 点路径语义匹配事件流、命中产出 pipeline.Alert。Handle 非阻塞
// （队列满丢弃计数），匹配在 worker 池中执行，绝不阻塞 ingest 主路径。
package rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/xycxmz/xiezhi-public/proto"
	"github.com/xycxmz/xiezhi-public/server/internal/pipeline"
)

const (
	defaultQueueCap   = 8192
	defaultWorkers    = 2
	defaultPollEvery  = time.Second
	defaultRateLimit  = 10 // 单规则每 agent 每窗口告警数
	defaultRateWindow = time.Minute
	eventRefMaxBytes  = 4096
)

// EmitUnpopulated 让零值字段（如 CRED_CHANGE 的 new_uid=0）也出现在匹配树里
// ——默认 protojson 会省略它们，而 uid=0 恰是提权规则要匹配的值。
// 未设置的 oneof 分支不受此开关影响，仍然不出现。
var marshalOpts = protojson.MarshalOptions{EmitUnpopulated: true}

// eventRoot 把事件 protojson 成 map（匹配树）并保留原始 JSON（EventRef 用）。
func eventRoot(ev *pb.Event) (root map[string]any, raw string, err error) {
	b, err := marshalOpts.Marshal(ev)
	if err != nil {
		return nil, "", err
	}
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, "", err
	}
	return root, string(b), nil
}

type job struct {
	ctx               context.Context
	ev                *pb.Event
	agentID, hostname string
	tsMs              int64
	et                pb.EventType
}

// Engine 是 pipeline.Handler 的规则引擎实现。
type Engine struct {
	dir       string
	sink      pipeline.Sink
	queue     chan *job
	done      chan struct{}
	closeOnce sync.Once
	workWG    sync.WaitGroup
	pollWG    sync.WaitGroup
	pollEvery time.Duration
	rules     atomic.Pointer[ruleset]
	lim       *limiter

	eventsIn, eventsDropped, eventsProcessed atomic.Uint64
	alertsEmitted, alertsLimited             atomic.Uint64
	panics, reloads, rejected, marshalErrs   atomic.Uint64
	lastAlertAt                              atomic.Int64
}

// Option 微调引擎参数；New 的固定入参签名不受影响。
type Option func(*Engine)

func WithQueueCap(n int) Option {
	return func(e *Engine) {
		if n > 0 {
			e.queue = make(chan *job, n)
		}
	}
}

// WithAlertRateLimit 设置单规则每 agent 的告警限速（perMinute 次每 window）。
func WithAlertRateLimit(perMinute int, window time.Duration) Option {
	return func(e *Engine) {
		if perMinute > 0 && window > 0 {
			e.lim = newLimiter(perMinute, window)
		}
	}
}

func WithPollInterval(d time.Duration) Option {
	return func(e *Engine) {
		if d > 0 {
			e.pollEvery = d
		}
	}
}

// Stats 是引擎运行计数快照（监控/测试可观察面）。
type Stats struct {
	RulesLoaded     int    // 当前规则集内规则数
	RulesRejected   uint64 // 累计跳过的坏/重复规则（含历次热更）
	Version         string // 当前规则集内容哈希
	Reloads         uint64
	EventsIn        uint64
	EventsDropped   uint64 // 队列满丢弃
	EventsProcessed uint64
	AlertsEmitted   uint64
	AlertsLimited   uint64 // 限速丢弃
	Panics          uint64 // Handle/worker 恢复的 panic 数
	// LastAlertMs 最后一次告警的墙钟 UnixMilli；0=从未。静默失效 watchdog
	// 判据：EventsIn 持续高位而此值长期不动（04:21 停报轮的教训——计数全绿
	// 不等于链路在出活）。
	LastAlertMs int64
}

func New(dir string, sink pipeline.Sink, opts ...Option) (*Engine, error) {
	if sink == nil {
		return nil, errors.New("rules: sink 不能为空")
	}
	res, err := loadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("rules: 加载规则目录 %s: %w", dir, err)
	}
	e := &Engine{
		dir:       dir,
		sink:      sink,
		queue:     make(chan *job, defaultQueueCap),
		done:      make(chan struct{}),
		pollEvery: defaultPollEvery,
		lim:       newLimiter(defaultRateLimit, defaultRateWindow),
	}
	for _, o := range opts {
		o(e)
	}
	e.rules.Store(res.set)
	e.rejected.Store(uint64(res.rejected))
	for i := 0; i < defaultWorkers; i++ {
		e.workWG.Add(1)
		go e.worker()
	}
	e.pollWG.Add(1)
	go e.poll()
	slog.Info("rules: 引擎启动", "dir", dir, "rules", res.set.total, "rejected", res.rejected, "version", res.set.version)
	return e, nil
}

func (e *Engine) Name() string { return "rules" }

// Handle 快速入队即返：队列满丢弃计数，绝不停等 worker。
// 竞态修复（R1.1）：queue 永不 close（close 后 select 有 ~50% 概率选中
// send-on-closed 分支 panic，旧版靠 recover 吞掉是不对的）——改为 done
// 信号驱动 worker 排空退出，Handle 只做非阻塞发送到永不关闭的 channel。
func (e *Engine) Handle(ctx context.Context, ev *pb.Event) {
	if ev == nil || ev.Header == nil {
		return
	}
	select {
	case <-e.done:
		return // 已关停，丢弃
	default:
	}
	h := ev.Header
	j := &job{
		ctx:      ctx,
		ev:       ev,
		agentID:  h.AgentId,
		hostname: h.Hostname,
		tsMs:     int64(h.TsMs),
		et:       h.EventType,
	}
	select {
	case e.queue <- j:
		e.eventsIn.Add(1)
	case <-e.done:
	default:
		e.eventsDropped.Add(1)
	}
}

func (e *Engine) Close() {
	e.closeOnce.Do(func() {
		close(e.done)
		e.pollWG.Wait()
		// queue 不 close（上述竞态的根修）——worker 收到 done 后排空再退出
		e.workWG.Wait()
	})
}

func (e *Engine) worker() {
	defer e.workWG.Done()
	for {
		select {
		case j := <-e.queue:
			e.process(j)
		case <-e.done:
			// 排空剩余积压后退出（queue 未 close，default 即空）
			for {
				select {
				case j := <-e.queue:
					e.process(j)
				default:
					return
				}
			}
		}
	}
}

func (e *Engine) process(j *job) {
	defer func() {
		if r := recover(); r != nil {
			e.panics.Add(1)
			slog.Warn("rules: worker panic 已恢复", "panic", r)
		}
	}()
	root, raw, err := eventRoot(j.ev)
	if err != nil {
		e.marshalErrs.Add(1)
		slog.Warn("rules: 事件 protojson 失败", "err", err)
		return
	}
	rs := e.rules.Load()
	now := time.Now()
	for _, rule := range rs.byEvent[j.et] {
		hit, desc := rule.matches(root)
		if !hit {
			continue
		}
		if !e.lim.allow(rule.id+"|"+j.agentID, now) {
			e.alertsLimited.Add(1)
			continue
		}
		// 告警是事件的派生物：父 ctx 取消不应阻止落盘，只保留取值链路。
		e.sink.EmitAlert(context.WithoutCancel(j.ctx), &pipeline.Alert{
			TsMs:     j.tsMs,
			AgentID:  j.agentID,
			Hostname: j.hostname,
			RuleID:   rule.id,
			Severity: rule.severity,
			Mitre:    rule.mitre,
			Summary:  truncRunes(rule.id+" "+desc, 256),
			EventRef: truncBytes(raw, eventRefMaxBytes),
		})
		e.alertsEmitted.Add(1)
		e.lastAlertAt.Store(time.Now().UnixMilli())
	}
	e.eventsProcessed.Add(1)
}

// poll 每 tick 比对目录内容哈希，变化时整体换规则快照；顺带清理限速桶。
func (e *Engine) poll() {
	defer e.pollWG.Done()
	t := time.NewTicker(e.pollEvery)
	defer t.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-t.C:
			d, err := dirDigest(e.dir)
			if err != nil {
				slog.Warn("rules: 轮询目录失败", "err", err)
				continue
			}
			if d == e.rules.Load().version {
				e.lim.prune(time.Now())
				continue
			}
			res, err := loadDir(e.dir)
			if err != nil {
				slog.Warn("rules: 热更加载失败", "err", err)
				continue
			}
			e.rules.Store(res.set)
			e.reloads.Add(1)
			e.rejected.Add(uint64(res.rejected))
			slog.Info("rules: 热更完成", "version", res.set.version, "rules", res.set.total, "rejected", res.rejected)
			e.lim.prune(time.Now())
		}
	}
}

func (e *Engine) Stats() Stats {
	rs := e.rules.Load()
	return Stats{
		RulesLoaded:     rs.total,
		RulesRejected:   e.rejected.Load(),
		Version:         rs.version,
		Reloads:         e.reloads.Load(),
		EventsIn:        e.eventsIn.Load(),
		EventsDropped:   e.eventsDropped.Load(),
		EventsProcessed: e.eventsProcessed.Load(),
		AlertsEmitted:   e.alertsEmitted.Load(),
		AlertsLimited:   e.alertsLimited.Load(),
		Panics:          e.panics.Load(),
		LastAlertMs:     e.lastAlertAt.Load(),
	}
}

// RuleInfo 是控制台规则清单项（/api/rules）。
type RuleInfo struct {
	ID       string `json:"id"`
	Event    string `json:"event"`
	Severity string `json:"severity"`
	Mitre    string `json:"mitre"`
}

// RuleSnapshot 返回当前规则集清单（按 id 排序，读原子指针无锁竞争）。
func (e *Engine) RuleSnapshot() []RuleInfo {
	rs := e.rules.Load()
	out := make([]RuleInfo, 0, rs.total)
	for _, crs := range rs.byEvent {
		for _, r := range crs {
			out = append(out, RuleInfo{
				ID: r.id, Event: r.eventType.String(),
				Severity: r.severity, Mitre: r.mitre,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// limiter 是 (rule|agent) 键的固定窗口限速，防单规则告警风暴。
type bucket struct {
	start, last int64
	n           int
}

type limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	limit    int
	windowMs int64
}

func newLimiter(limit int, window time.Duration) *limiter {
	return &limiter{buckets: make(map[string]*bucket, 64), limit: limit, windowMs: window.Milliseconds()}
}

func (l *limiter) allow(key string, now time.Time) bool {
	nowMs := now.UnixMilli()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil || nowMs-b.start >= l.windowMs {
		b = &bucket{start: nowMs}
		l.buckets[key] = b
	}
	b.last = nowMs
	if b.n >= l.limit {
		return false
	}
	b.n++
	return true
}

// prune 清理 10 个窗口未活跃的桶，防 agent×规则笛卡尔积无限增长。
func (l *limiter) prune(now time.Time) {
	threshold := now.UnixMilli() - 10*l.windowMs
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.last < threshold {
			delete(l.buckets, k)
		}
	}
}

func truncBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

var _ pipeline.Handler = (*Engine)(nil)
