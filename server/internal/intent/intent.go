// SPDX-License-Identifier: Apache-2.0

// Package intent 实现意图标签层最小闭环：EXECVE 命令行 →
// Labeler 打标签 → 策略文件打分 → 会话桶滑动窗口累加 → 过阈值告警。
// 设计依据：SecEBL 的 L2 本质是「标签→风险分」静态规则引擎，
// 本层不依赖任何训练。
//
// 三件事大声声明：
//
//  1. builtin 标注器是占位实现——关键词→标签的确定性映射表，不是语义模型。
//     SecEBL sidecar 部署后（XIEZHI_LABELER=http + XIEZHI_LABELER_URL），由
//     HTTP 标注器整体替换，本层其余逻辑不变。
//  2. 会话累加桶用 (host, uid) 简化。按 startTicks 进程树归并到根需要跨
//     事件 ppid 链的精确维护，M4 不具备（M5 session 层的 per-host 进程树
//     才有树根）；代价是同一 uid 的多个 shell 并入同一桶。M5 集成路径：
//     把桶键从 (host, uid) 换成 session.Handler 的树根标识即可，桶与
//     打分逻辑不动。
//  3. 策略文件缺失 = 本层整体旁路：不告警不算分，只计 PolicyBypassed。
//     文件出现/恢复后 1s 轮询热更自动恢复。标签层旁路
//     要求任何失败都退化为「无意图信号」，绝不阻塞事件流。
package intent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/xycxmz/xiezhi-public/proto"
	"github.com/xycxmz/xiezhi-public/server/internal/pipeline"
)

const (
	defaultQueueCap  = 8192
	defaultWorkers   = 2
	defaultPollEvery = time.Second
	defaultWindow    = 10 * time.Minute

	cmdlineMaxBytes  = 1024 // 标注输入上界：argv join 后截 1KB
	summaryMaxRunes  = 256
	eventRefMaxBytes = 4096

	// severity 按折后桶总分分档（brief 冻结：≥8 high，≥5 medium，else low）。
	sevHighScore   = 8.0
	sevMediumScore = 5.0
)

// Label 是标注器的输出：Tag 为标签名（策略文件 tags 键），Score 为置信度
// （builtin 恒 1.0；http 标注器为 sidecar 返回值）。
type Label struct {
	Tag   string  `json:"tag"`
	Score float64 `json:"score"`
}

// Labeler 把命令行映射为零或多个标签。失败必须返回空标签（旁路语义），
// 不允许向调用方报错。
type Labeler interface {
	Label(ctx context.Context, cmdline string) []Label
}

// NewLabelerFromEnv 按 XIEZHI_LABELER（builtin|http，默认 builtin）构造标注器。
// http 需要 XIEZHI_LABELER_URL。
func NewLabelerFromEnv() (Labeler, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("XIEZHI_LABELER")))
	switch mode {
	case "", "builtin":
		return NewBuiltin(), nil
	case "http":
		u := strings.TrimSpace(os.Getenv("XIEZHI_LABELER_URL"))
		if u == "" {
			return nil, errors.New("intent: XIEZHI_LABELER=http 但 XIEZHI_LABELER_URL 未设置")
		}
		return NewHTTPLabeler(u, 2*time.Second), nil
	default:
		return nil, fmt.Errorf("intent: 未知 XIEZHI_LABELER 值 %q（builtin|http）", mode)
	}
}

type job struct {
	ctx               context.Context
	ev                *pb.Event
	agentID, hostname string
	tsMs              int64
}

// Handler 是 pipeline.Handler 的意图层实现。Handle 非阻塞（队列满丢弃
// 计数），标注与累加在 worker 池执行。
type Handler struct {
	labeler    Labeler
	sink       pipeline.Sink
	policyPath string
	rootFinder RootFinder // R4.3: session tree root for bucket key upgrade (nil = host+uid fallback)

	queue     chan *job
	done      chan struct{}
	closeOnce sync.Once
	workWG    sync.WaitGroup
	pollWG    sync.WaitGroup
	pollEvery time.Duration
	window    time.Duration

	pol     atomic.Pointer[policy] // nil = 本层旁路
	buckets *bucketStore

	eventsIn, eventsDropped, eventsProcessed atomic.Uint64
	policyBypassed, labelerEmpty, alerts     atomic.Uint64
	reloads, rejected, panics                atomic.Uint64
	lastAlertAt                              atomic.Int64
}

// RootFinder maps a process to its session tree root (R4.3).
// Implemented by session.Handler.RootFinder(); defined here to avoid
// a cross-package dependency.
type RootFinder interface {
	FindRoot(host string, pid int32) (root SessionRoot, ok bool)
}

// SessionRoot mirrors session.SessionRoot (structural typing, no import).
type SessionRoot struct {
	RootPid   int32
	RootTicks uint64
	RootExe   string
}

// Option 微调参数；New 的固定入参签名不受影响。
type Option func(*Handler)

func WithQueueCap(n int) Option {
	return func(h *Handler) {
		if n > 0 {
			h.queue = make(chan *job, n)
		}
	}
}

func WithPollInterval(d time.Duration) Option {
	return func(h *Handler) {
		if d > 0 {
			h.pollEvery = d
		}
	}
}

func WithWindow(d time.Duration) Option {
	return func(h *Handler) {
		if d > 0 {
			h.window = d
		}
	}
}

// WithRootFinder enables session tree root bucket keys (R4.3).
// When set, intent buckets key on (host, rootPid) instead of (host, uid).
func WithRootFinder(rf RootFinder) Option {
	return func(h *Handler) {
		h.rootFinder = rf
	}
}

// New 构造意图层 handler。policyPath 缺失不报错（本层旁路，大声告警日志）；
// 存在但内容非法则报错——启动期配置错误应 fail fast，运行期热更失败才沿用旧策略。
func New(labeler Labeler, sink pipeline.Sink, policyPath string, opts ...Option) (*Handler, error) {
	if labeler == nil {
		return nil, errors.New("intent: labeler 不能为空")
	}
	if sink == nil {
		return nil, errors.New("intent: sink 不能为空")
	}
	h := &Handler{
		labeler:    labeler,
		sink:       sink,
		policyPath: policyPath,
		queue:      make(chan *job, defaultQueueCap),
		done:       make(chan struct{}),
		pollEvery:  defaultPollEvery,
		window:     defaultWindow,
	}
	for _, o := range opts {
		o(h)
	}
	pol, missing, err := loadPolicy(policyPath)
	if err != nil {
		return nil, fmt.Errorf("intent: 策略文件 %s: %w", policyPath, err)
	}
	switch {
	case pol != nil:
		h.pol.Store(pol)
		slog.Info("intent: 策略已加载", "path", policyPath, "tags", len(pol.tags), "threshold", pol.threshold, "version", pol.version)
	case missing:
		slog.Warn("intent: 策略文件缺失，本层旁路（不告警不算分），文件出现后热更恢复", "path", policyPath)
	}
	h.buckets = newBucketStore(h.window)
	for i := 0; i < defaultWorkers; i++ {
		h.workWG.Add(1)
		go h.worker()
	}
	h.pollWG.Add(1)
	go h.poll()
	return h, nil
}

func (h *Handler) Name() string { return "intent" }

// Handle 快速入队即返：只收 EXECVE，队列满丢弃计数，绝不停等 worker。
func (h *Handler) Handle(ctx context.Context, ev *pb.Event) {
	defer func() {
		if r := recover(); r != nil {
			h.panics.Add(1)
			slog.Warn("intent: Handle panic 已恢复", "panic", r)
		}
	}()
	if ev == nil || ev.Header == nil || ev.Header.EventType != pb.EventType_EXECVE {
		return
	}
	if ev.GetExecve().GetProc() == nil {
		return
	}
	select {
	case <-h.done:
		return
	default:
	}
	j := &job{
		ctx:      ctx,
		ev:       ev,
		agentID:  ev.Header.AgentId,
		hostname: ev.Header.Hostname,
		tsMs:     int64(ev.Header.TsMs),
	}
	select {
	case h.queue <- j:
		h.eventsIn.Add(1)
	case <-h.done:
	default:
		h.eventsDropped.Add(1)
	}
}

// Close 停轮询、停 worker。刻意不 close 队列：queue 与 done 双 closed 时
// select 会以约 50% 概率选中 send-on-closed 分支而 panic（.scratch 实验
// 100000 次命中 50174 次），靠 recover 吞掉是把竞态当控制流。worker 在
// done 后自行排空积压再退出，语义与 close(queue)+range 等价且无竞态。
func (h *Handler) Close() {
	h.closeOnce.Do(func() {
		close(h.done)
		h.pollWG.Wait()
		h.workWG.Wait()
	})
}

func (h *Handler) worker() {
	defer h.workWG.Done()
	for {
		select {
		case j := <-h.queue:
			h.process(j)
		case <-h.done:
			for {
				select {
				case j := <-h.queue:
					h.process(j)
				default:
					return
				}
			}
		}
	}
}

func (h *Handler) process(j *job) {
	defer func() {
		if r := recover(); r != nil {
			h.panics.Add(1)
			slog.Warn("intent: worker panic 已恢复", "panic", r)
		}
	}()
	defer h.eventsProcessed.Add(1)
	pol := h.pol.Load()
	if pol == nil {
		h.policyBypassed.Add(1)
		return
	}
	proc := j.ev.GetExecve().GetProc()
	cmdline := joinArgv(proc.GetArgv())
	// 标注不受父 ctx 取消影响：ingest RPC 可能已返回，取值仍应完成。
	labels := h.labeler.Label(context.WithoutCancel(j.ctx), cmdline)
	if len(labels) == 0 {
		h.labelerEmpty.Add(1)
		return
	}
	hits := contributing(labels, pol)
	if len(hits) == 0 {
		return
	}
	ts := j.tsMs
	if ts <= 0 {
		ts = time.Now().UnixMilli()
	}
	// R4.3: upgrade bucket key to session tree root when available.
	var rootPid int32
	if h.rootFinder != nil {
		if root, ok := h.rootFinder.FindRoot(j.hostname, int32(proc.GetPid())); ok {
			rootPid = root.RootPid
		}
	}
	res := h.buckets.add(j.hostname, proc.GetUid(), rootPid, ts, hits, pol)
	if !res.crossed {
		return
	}
	h.emit(j, ts, pol, hits, res)
	h.alerts.Add(1)
	h.lastAlertAt.Store(time.Now().UnixMilli())
}

// contributing 过滤出策略分值表覆盖的标签并按 tag 去重（同名取分高者）。
func contributing(labels []Label, pol *policy) []Label {
	best := make(map[string]Label, len(labels))
	for _, l := range labels {
		if _, ok := pol.tags[l.Tag]; !ok {
			continue
		}
		if cur, dup := best[l.Tag]; !dup || l.Score > cur.Score {
			best[l.Tag] = l
		}
	}
	hits := make([]Label, 0, len(best))
	for _, l := range best {
		hits = append(hits, l)
	}
	return hits
}

// primaryTag 取本次事件中贡献分最高的标签（并列取字典序最小，保证确定性）。
func primaryTag(hits []Label, pol *policy) string {
	best := ""
	var bestPts float64
	for _, l := range hits {
		pts := pol.tags[l.Tag] * l.Score
		if best == "" || pts > bestPts || (pts == bestPts && l.Tag < best) {
			best, bestPts = l.Tag, pts
		}
	}
	return best
}

// emit 落意图告警。tsMs 是桶累加用的同一时间戳（含缺时钟 now 回退），
// 避免缺时钟 agent 的告警 TsMs 原样透传 0 落库成 1970。
func (h *Handler) emit(j *job, tsMs int64, pol *policy, hits []Label, res addResult) {
	var eventPts float64
	for _, l := range hits {
		eventPts += pol.tags[l.Tag] * l.Score
	}
	tags := make([]string, 0, len(res.tagPts))
	for tag, pts := range res.tagPts {
		tags = append(tags, fmt.Sprintf("%s:%.1f", tag, pts))
	}
	sort.Strings(tags)
	summary := fmt.Sprintf("intent/%s 标签=[%s] 本次+%.1f 桶累计=%.1f/阈值%.1f",
		primaryTag(hits, pol), strings.Join(tags, " "), eventPts, res.total, pol.threshold)
	if res.discounted {
		summary += fmt.Sprintf(" 含维护衰减x%.2f", pol.maintDiscount)
	}
	raw, err := marshalOpts.Marshal(j.ev)
	if err != nil {
		raw = nil
		slog.Warn("intent: 事件 protojson 失败，EventRef 留空", "err", err)
	}
	h.sink.EmitAlert(context.WithoutCancel(j.ctx), &pipeline.Alert{
		TsMs:     tsMs,
		AgentID:  j.agentID,
		Hostname: j.hostname,
		RuleID:   "intent/" + primaryTag(hits, pol),
		Severity: severityOf(res.total),
		Summary:  truncRunes(summary, summaryMaxRunes),
		EventRef: truncBytes(string(raw), eventRefMaxBytes),
	})
}

func severityOf(total float64) string {
	switch {
	case total >= sevHighScore:
		return "high"
	case total >= sevMediumScore:
		return "medium"
	default:
		return "low"
	}
}

// poll 每 tick 热更策略并清扫过期桶。
func (h *Handler) poll() {
	defer h.pollWG.Done()
	t := time.NewTicker(h.pollEvery)
	defer t.Stop()
	for {
		select {
		case <-h.done:
			return
		case <-t.C:
			h.reloadIfChanged()
			h.buckets.sweep(time.Now().UnixMilli())
		}
	}
}

func (h *Handler) reloadIfChanged() {
	pol, missing, err := loadPolicy(h.policyPath)
	switch {
	case err != nil:
		h.rejected.Add(1)
		slog.Warn("intent: 策略热更加载失败，沿用旧策略", "err", err)
		return
	case missing:
		if h.pol.Load() != nil {
			h.pol.Store(nil)
			h.reloads.Add(1)
			slog.Warn("intent: 策略文件消失，本层旁路（不告警不算分）", "path", h.policyPath)
		}
		return
	}
	if cur := h.pol.Load(); cur != nil && cur.version == pol.version {
		return
	}
	h.pol.Store(pol)
	h.reloads.Add(1)
	slog.Info("intent: 策略热更完成", "version", pol.version, "tags", len(pol.tags), "threshold", pol.threshold)
}

// Stats 是运行计数快照（监控/测试可观察面）。
type Stats struct {
	PolicyActive    bool
	PolicyVersion   string
	PolicyTags      int
	Threshold       float64
	Reloads         uint64 // 成功热更次数（含进入/退出旁路的切换）
	Rejected        uint64 // 热更加载失败次数（沿用旧策略）
	EventsIn        uint64
	EventsDropped   uint64
	EventsProcessed uint64
	PolicyBypassed  uint64 // 策略缺失期间流入的 EXECVE 数
	LabelerFails    uint64 // http 标注器失败次数（builtin 恒 0）
	LabelerEmpty    uint64 // 标注返回空标签（含失败旁路）的事件数
	AlertsEmitted   uint64
	Panics          uint64
	Buckets         int
	// LastAlertMs 最后一次告警的墙钟 UnixMilli；0=从未。与 rules 同款
	// watchdog 判据（04:21 停报轮教训）。
	LastAlertMs int64
}

func (h *Handler) Stats() Stats {
	pol := h.pol.Load()
	st := Stats{
		Reloads:         h.reloads.Load(),
		Rejected:        h.rejected.Load(),
		EventsIn:        h.eventsIn.Load(),
		EventsDropped:   h.eventsDropped.Load(),
		EventsProcessed: h.eventsProcessed.Load(),
		PolicyBypassed:  h.policyBypassed.Load(),
		LabelerEmpty:    h.labelerEmpty.Load(),
		AlertsEmitted:   h.alerts.Load(),
		Panics:          h.panics.Load(),
		Buckets:         h.buckets.count(),
		LastAlertMs:     h.lastAlertAt.Load(),
	}
	if pol != nil {
		st.PolicyActive = true
		st.PolicyVersion = pol.version
		st.PolicyTags = len(pol.tags)
		st.Threshold = pol.threshold
	}
	if f, ok := h.labeler.(interface{ Fails() uint64 }); ok {
		st.LabelerFails = f.Fails()
	}
	return st
}

// EmitUnpopulated 与规则引擎同款：零值字段（uid=0 等）也进 EventRef。
var marshalOpts = protojson.MarshalOptions{EmitUnpopulated: true}

// joinArgv 拼接 argv 并在 rune 边界上截 1KB（标注输入上界：超出部分对
// 标注器不可见，也限住传给 sidecar 的请求体大小）。
func joinArgv(argv []string) string {
	return truncRunes(strings.Join(argv, " "), cmdlineMaxBytes)
}

func truncRunes(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := s[:limit]
	// 退到完整 rune 边界：末字节是 ASCII 或续字节（rune 的最后一字节）
	// 即完整；多字节首字节悬挂则丢弃该残 rune。
	for len(cut) > 0 {
		b := cut[len(cut)-1]
		if b < utf8.RuneSelf || b&0xC0 == 0x80 {
			break
		}
		cut = cut[:len(cut)-1]
	}
	return cut
}

func truncBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

var _ pipeline.Handler = (*Handler)(nil)
