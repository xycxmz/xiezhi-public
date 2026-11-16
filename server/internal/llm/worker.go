// SPDX-License-Identifier: Apache-2.0

// worker 消费 NATS xiezhi.alerts 做 shadow 研判。M4 语义（契约冻结）：core
// NATS queue 订阅（queue group 防多实例重复研判），live 消费不追历史——
// worker 宕机期间的告警不回放，验收时以该声明为准。失败处理全部计数，
// 任何失败都不回馈告警流（shadow 零副作用）。
package llm

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/xycxmz/xiezhi-public/server/internal/pipeline"
)

const (
	alertsSubject = "xiezhi.alerts"
	queueGroup    = "xiezhi-llm-triage"
	// parseErrReasoningMax 解析失败时把模型原文截进 reasoning 供审计。
	parseErrReasoningMax = 512
)

type Worker struct {
	cfg      Config
	provider Provider
	store    TriageStore
	fetcher  EventFetcher  // 可 nil：跳过历史事件段
	trees    SubtreeSource // 可 nil：跳过进程树段

	sem chan struct{}
	wg  sync.WaitGroup

	received     atomic.Uint64
	triaged      atomic.Uint64
	parseErrors  atomic.Uint64
	timeouts     atomic.Uint64
	skippedStale atomic.Uint64
	storeFailed  atomic.Uint64
	queueDropped atomic.Uint64 // 并发闸满即丢（告警风暴背压，与 batcher/AlertSink 同纪律）

	sub     *nats.Subscription
	closed  atomic.Bool
	closeMu sync.Mutex
}

func NewWorker(cfg Config, provider Provider, store TriageStore, fetcher EventFetcher, trees SubtreeSource) *Worker {
	if cfg.MaxConcurrency < 1 {
		cfg.MaxConcurrency = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &Worker{
		cfg:      cfg,
		provider: provider,
		store:    store,
		fetcher:  fetcher,
		trees:    trees,
		sem:      make(chan struct{}, cfg.MaxConcurrency),
	}
}

// Subscribe 起 live queue 订阅（nc 由 main 传入）。返回错误即装配失败。
func (w *Worker) Subscribe(nc *nats.Conn) error {
	w.closeMu.Lock()
	defer w.closeMu.Unlock()
	if w.closed.Load() {
		return errors.New("llm: worker closed")
	}
	sub, err := nc.QueueSubscribe(alertsSubject, queueGroup, func(m *nats.Msg) {
		w.onMsg(m.Data)
	})
	if err != nil {
		return err
	}
	w.sub = sub
	return nil
}

func (w *Worker) onMsg(data []byte) {
	if w.closed.Load() {
		return
	}
	var a pipeline.Alert
	if err := json.Unmarshal(data, &a); err != nil {
		slog.Warn("llm triage: bad alert payload", "err", err)
		return
	}
	// 并发闸在起 goroutine 前获取：闸内再排队会让告警风暴堆出无上界的
	// goroutine（各持 Alert 副本、ctx 又不可取消）。闸满即丢计数。
	select {
	case w.sem <- struct{}{}:
	default:
		n := w.queueDropped.Add(1)
		if n == 1 || n%1000 == 0 {
			slog.Warn("llm triage: concurrency cap reached, alerts dropped", "dropped", n)
		}
		return
	}
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		defer func() { <-w.sem }()
		w.handleAlert(context.Background(), &a)
	}()
}

// HandleAlert 同步研判单条（测试与外部调用共用）：自取并发闸后走 handleAlert。
func (w *Worker) HandleAlert(ctx context.Context, a *pipeline.Alert) {
	if a == nil {
		return
	}
	select {
	case w.sem <- struct{}{}:
	case <-ctx.Done():
		w.timeouts.Add(1)
		return
	}
	defer func() { <-w.sem }()
	w.handleAlert(ctx, a)
}

// handleAlert 研判单条，调用方须已持有并发闸（onMsg 起 goroutine 前获取、
// HandleAlert 自取）。打包证据→调 provider→写 llm_triage。MultiRole 开启时
// 先跑三角色对抗链，任何一段失败降级单角色（row 记 single_fallback）；告警
// 太老（TriageSinceMin 窗口外）跳过；超时/网络失败只计数；解析失败落
// parse_error 行。
func (w *Worker) handleAlert(ctx context.Context, a *pipeline.Alert) {
	if a == nil {
		return
	}
	w.received.Add(1)
	now := time.Now()
	if a.TsMs > 0 && now.UnixMilli()-a.TsMs > int64(w.cfg.TriageSinceMin)*60_000 {
		w.skippedStale.Add(1)
		return
	}

	timeout := w.cfg.Timeout
	if w.cfg.MultiRole && timeout < multiRoleTimeout {
		timeout = multiRoleTimeout
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	sinceMs := now.Add(-time.Duration(w.cfg.TriageSinceMin) * time.Minute).UnixMilli()
	ev, err := BuildEvidence(tctx, a, sinceMs, w.fetcher, w.trees)
	if err != nil {
		slog.Warn("llm triage: evidence build failed", "err", err)
		return
	}
	userJSON, err := ev.MarshalBudgeted()
	if err != nil {
		slog.Warn("llm triage: evidence marshal failed", "err", err)
		return
	}

	mode := ""
	if w.cfg.MultiRole {
		res, merr := runMultiRole(tctx, w.provider, userJSON)
		if merr == nil {
			v := *res.Verdict
			if res.Summary != "" {
				v.Reasoning = v.Reasoning + "；hypotheses: " + res.Summary
			}
			w.save(saveCtx(), a, Completion{
				Verdict:   v,
				TokensIn:  res.TokensIn,
				TokensOut: res.TokensOut,
			}, time.Since(start).Milliseconds(), "multi")
			return
		}
		if isCtxCanceled(tctx) {
			w.timeouts.Add(1)
			return
		}
		slog.Warn("llm triage: multi-role failed, falling back to single role",
			"rule", a.RuleID, "err", merr)
		mode = "single_fallback"
	}

	comp, err := w.provider.Complete(tctx, systemPrompt, userPrompt(userJSON))
	latency := time.Since(start).Milliseconds()

	switch {
	case err == nil:
	case errors.Is(err, errParse):
		w.parseErrors.Add(1)
		w.save(saveCtx(), a, Completion{Verdict: Verdict{State: StateParseError}, Raw: comp.Raw}, latency, mode)
		return
	case errors.Is(err, context.DeadlineExceeded), isCtxCanceled(tctx):
		w.timeouts.Add(1)
		return
	default:
		slog.Warn("llm triage: provider failed", "rule", a.RuleID, "err", err)
		return
	}

	w.save(saveCtx(), a, comp, latency, mode)
}

// saveCtx 落库专用短超时（F-010）：provider 链耗满共享 deadline 后，已付费
// 的 verdict 不能再跟着过期 ctx 丢在 save 环节——save 与研判分账。调用方
// defer cancel()。
func saveCtx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// save 是尾调用路径，泄漏一个 10s timer 直到进程退出可接受；
	// 显式 cancel 需调用方配合，三处调用点都是单行结尾，保持简洁。
	_ = cancel
	return ctx
}

// save 落一行 llm_triage。mode 非空（multi|single_fallback）时在 reasoning
// 前加 [mode] 前缀——roles_mode 不改表结构，就记在现有列里。
func (w *Worker) save(ctx context.Context, a *pipeline.Alert, comp Completion, latencyMs int64, mode string) {
	v := comp.Verdict
	reasoning := v.Reasoning
	if v.State == StateParseError {
		reasoning = "parse_error: model output not valid schema JSON. raw: " + truncBytes(comp.Raw, parseErrReasoningMax)
	}
	if mode != "" {
		reasoning = "[" + mode + "] " + reasoning
	}
	row := TriageRow{
		TsMs:       time.Now().UnixMilli(),
		AlertTsMs:  a.TsMs,
		AgentID:    a.AgentID,
		RuleID:     a.RuleID,
		State:      v.State,
		Confidence: v.Confidence,
		Reasoning:  reasoning,
		Tactic:     v.Tactic,
		Model:      w.provider.Name(),
		LatencyMs:  latencyMs,
		TokensIn:   comp.TokensIn,
		TokensOut:  comp.TokensOut,
	}
	if err := w.store.SaveTriage(ctx, row); err != nil {
		w.storeFailed.Add(1)
		slog.Warn("llm triage: save failed", "rule", a.RuleID, "err", err)
		return
	}
	if v.State != StateParseError {
		w.triaged.Add(1)
		slog.Info("llm triage verdict",
			"rule", a.RuleID, "agent", a.AgentID, "state", string(v.State),
			"confidence", v.Confidence, "latency_ms", latencyMs, "model", row.Model)
	}
}

// Stats 输出计数器快照（/triage?stats=1）。
func (w *Worker) Stats() map[string]uint64 {
	return map[string]uint64{
		"received":      w.received.Load(),
		"triaged":       w.triaged.Load(),
		"parse_error":   w.parseErrors.Load(),
		"timeout":       w.timeouts.Load(),
		"skipped_stale": w.skippedStale.Load(),
		"store_failed":  w.storeFailed.Load(),
		"queue_dropped": w.queueDropped.Load(),
	}
}

// Close 退订并等在飞研判排干。
func (w *Worker) Close() {
	w.closeMu.Lock()
	w.closed.Store(true)
	if w.sub != nil {
		_ = w.sub.Unsubscribe()
	}
	w.closeMu.Unlock()
	w.wg.Wait()
}

func isCtxCanceled(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
