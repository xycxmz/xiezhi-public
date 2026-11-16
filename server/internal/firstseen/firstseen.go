// SPDX-License-Identifier: Apache-2.0

// Package firstseen 实现 first-seen 全局基线（统计基线型异常检测
// 的最简形式，零训练成本覆盖未知威胁，规则层之外的最简补充，驭龙遗产）。
// 新键不逐条告警：exe 白名单前缀压掉系统路径噪声，其余按 host×kind 小时
// 聚合成 digest 告警（digest.go，M4 降噪）；PG 持久化权威 first_ts，内存
// LRU 吸收窗口内重复观察，批量管道压 PG 写放大。
package firstseen

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/xycxmz/xiezhi-public/proto"
	"github.com/xycxmz/xiezhi-public/server/internal/pipeline"
)

// Config 可调项。默认值即 brief 给定：LRU 100k 键 / TTL 10min；批量 100 键
// 或 500ms 攒批。
type Config struct {
	CacheKeys  int
	CacheTTL   time.Duration
	BatchKeys  int
	BatchEvery time.Duration
	QueueSize  int
}

func (c Config) withDefaults() Config {
	if c.CacheKeys <= 0 {
		c.CacheKeys = 100_000
	}
	if c.CacheTTL <= 0 {
		c.CacheTTL = 10 * time.Minute
	}
	if c.BatchKeys <= 0 {
		c.BatchKeys = 100
	}
	if c.BatchEvery <= 0 {
		c.BatchEvery = 500 * time.Millisecond
	}
	if c.QueueSize <= 0 {
		c.QueueSize = 8192
	}
	return c
}

type Handler struct {
	cfg   Config
	store Store
	sink  pipeline.Sink // 告警出口，归 main 所有，Close 不关它
	dig   *digest       // 新键降噪聚合（白名单+小时 digest），loop 单 goroutine 所有
	cache *ttlCache
	queue chan Obs

	dropped     atomic.Uint64
	flushFailed atomic.Uint64
	panics      atomic.Uint64

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func New(store Store, alertSink pipeline.Sink, cfg Config) *Handler {
	cfg = cfg.withDefaults()
	h := &Handler{
		cfg:   cfg,
		store: store,
		sink:  alertSink,
		dig:   newDigest(ExePrefixesFromEnv(), alertSink),
		cache: newTTLCache(cfg.CacheKeys, cfg.CacheTTL, nil),
		queue: make(chan Obs, cfg.QueueSize),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go h.loop()
	return h
}

func (h *Handler) Name() string { return "firstseen" }

// Handle 非阻塞：LRU O(1) 吸收 + 队列投递即返。队列满丢弃计数并踢出缓存
// （该键下个事件可重试）。recover 是 pipeline M3 契约：handler 自吞异常绝不
// 打断 ingest 主路径。
func (h *Handler) Handle(_ context.Context, ev *pb.Event) {
	defer h.recoverPanic("Handle")
	for _, o := range ExtractKeys(ev) {
		if !h.cache.AddIfAbsent(o.Key) {
			continue
		}
		if !h.enqueue(o) {
			h.dropped.Add(1)
		}
	}
}

// RegisterParentExe 注册父子孙观察（第四类键 exe_parent，无事件侧抽取，由
// session 在树归档时对树内每个 distinct exe 回填）。走同一管道：LRU 吸收 +
// 批量 upsert + 首见告警。签名即 session.ParentExeRegistrar——main 接线时
// *firstseen.Handler 直接满足该接口。
func (h *Handler) RegisterParentExe(_ context.Context, host, agentID, exe, parentExe string, tsMs int64) {
	defer h.recoverPanic("RegisterParentExe")
	if exe == "" || parentExe == "" {
		return
	}
	o := Obs{
		Key:     encodeKey(KindExeParent, sanitize(host), sanitize(exe), sanitize(parentExe)),
		Kind:    KindExeParent,
		Host:    host,
		AgentID: agentID,
		TsMs:    tsMs,
	}
	if !h.cache.AddIfAbsent(o.Key) {
		return
	}
	if !h.enqueue(o) {
		h.dropped.Add(1)
	}
}

func (h *Handler) enqueue(o Obs) bool {
	select {
	case h.queue <- o:
		return true
	default:
		h.cache.Remove(o.Key)
		return false
	}
}

// Close 停批量、排干队列做最后一次 flush、关自有的 store。
func (h *Handler) Close() {
	h.closeOnce.Do(func() {
		close(h.stop)
	})
	<-h.done
}

func (h *Handler) Dropped() uint64     { return h.dropped.Load() }
func (h *Handler) FlushFailed() uint64 { return h.flushFailed.Load() }
func (h *Handler) Panics() uint64      { return h.panics.Load() }

func (h *Handler) recoverPanic(where string) {
	if r := recover(); r != nil {
		h.panics.Add(1)
		slog.Error("firstseen panic recovered", "where", where, "panic", r)
	}
}

func (h *Handler) loop() {
	defer close(h.done)
	// 停机收尾：排干队列最后一次 flush 之后，把未满小时的 digest 窗口也发掉
	defer func() { h.dig.flushAll(time.Now()) }()
	defer func() {
		if err := h.store.Close(); err != nil {
			slog.Warn("firstseen store close", "err", err)
		}
	}()
	ticker := time.NewTicker(h.cfg.BatchEvery)
	defer ticker.Stop()
	digestTick := time.NewTicker(time.Hour)
	defer digestTick.Stop()
	buf := make([]Obs, 0, h.cfg.BatchKeys)
	for {
		select {
		case o := <-h.queue:
			buf = append(buf, o)
			if len(buf) >= h.cfg.BatchKeys {
				h.flush(&buf)
			}
		case <-ticker.C:
			h.flush(&buf)
		case <-digestTick.C:
			h.dig.flush(time.Now())
		case <-h.stop:
			for {
				select {
				case o := <-h.queue:
					buf = append(buf, o)
				default:
					h.flush(&buf)
					return
				}
			}
		}
	}
}

// mergeObs 批内合并同键：命中数累加进 Count（hit_count 语义=批窗口聚合后的
// 观测次数，非逐事件精确计数），ts 取最大保证 last_ts 单调。
func mergeObs(in []Obs) []Obs {
	idx := make(map[string]int, len(in))
	out := make([]Obs, 0, len(in))
	for _, o := range in {
		if o.Count < 1 {
			o.Count = 1
		}
		if i, ok := idx[o.Key]; ok {
			out[i].Count += o.Count
			if o.TsMs > out[i].TsMs {
				out[i].TsMs = o.TsMs
			}
			continue
		}
		idx[o.Key] = len(out)
		out = append(out, o)
	}
	return out
}

// flush 合并去重后批量 upsert。is_new 权威判定在 PG 层（xmax 技巧）；新键
// 交给 digest 聚合器（白名单压告警 / 小时 digest，见 digest.go）。批次失败
// 丢弃计数（与 store.Batcher 同纪律：存储故障不反压 ingest）——first_ts 迟
// 一个 LRU 窗口补录，期间可能多出一次重复告警，属可接受的降级模式。
func (h *Handler) flush(buf *[]Obs) {
	if len(*buf) == 0 {
		return
	}
	obs := mergeObs(*buf)
	*buf = (*buf)[:0]
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	newIdx, err := h.store.Upsert(ctx, obs)
	if err != nil {
		h.flushFailed.Add(uint64(len(obs)))
		slog.Error("firstseen upsert failed, batch discarded", "keys", len(obs), "err", err)
		return
	}
	for _, i := range newIdx {
		if i < 0 || i >= len(obs) {
			continue
		}
		h.dig.add(obs[i])
	}
}
