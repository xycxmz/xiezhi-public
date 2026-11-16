// SPDX-License-Identifier: Apache-2.0

package deadman

import (
	"context"
	"log/slog"
	"time"

	pb "github.com/xycxmz/xiezhi-public/proto"
	"github.com/xycxmz/xiezhi-public/server/internal/ingest"
	"github.com/xycxmz/xiezhi-public/server/internal/store"
)

// EventSink 与 ingest 同路：真实现为 sink.DualWrite（NATS+CH batcher）。
type EventSink interface {
	Write(row store.Row)
}

// Watchdog 周期扫描心跳视图：staleness 超阈值且云对账未排除 → AGENT_OFFLINE。
// 非并发安全：alerted 状态由 Run 的单扫描 goroutine 独占，测试直接串行调
// scanOnce。
type Watchdog struct {
	beats     *ingest.Heartbeats
	sink      EventSink
	recon     *Reconciler
	threshold time.Duration
	interval  time.Duration

	alerted map[string]bool // 未恢复（再次心跳）前不重复告警
}

func New(beats *ingest.Heartbeats, sink EventSink, recon *Reconciler, threshold, interval time.Duration) *Watchdog {
	return &Watchdog{
		beats:     beats,
		sink:      sink,
		recon:     recon,
		threshold: threshold,
		interval:  interval,
		alerted:   make(map[string]bool),
	}
}

func (w *Watchdog) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.scanOnce(ctx, time.Now())
		}
	}
}

// scanOnce 的判定序：先查已告警抑制（省一次对账），再对账，再重查新鲜度。
// 第三步是必须的：对账预算最多 10s，期间心跳可能恰好到达，凭扫描开头
// 的快照告警会误报刚恢复的 agent。
func (w *Watchdog) scanOnce(ctx context.Context, now time.Time) {
	for _, b := range w.beats.Snapshot() {
		if ctx.Err() != nil {
			// 停机中途不再起浪：避免关停时对剩余快照批量补发事件
			return
		}
		stale := now.Sub(time.UnixMilli(b.LastMs))
		if stale > w.threshold {
			if w.alerted[b.AgentID] {
				continue
			}
			state, staleCache := w.recon.State(ctx, b.AgentID)
			if state == powerStopped {
				// 关机机（正常关机待回收）：不告警只记 debug——
				// 这是本看门狗存在的核心理由
				slog.Debug("deadman suppressed, powered off",
					"agent_id", b.AgentID, "staleness_ms", stale.Milliseconds())
				continue
			}
			if last, ok := w.beats.Last(b.AgentID); ok && now.Sub(time.UnixMilli(last.LastMs)) <= w.threshold {
				continue
			}
			detail := ""
			if staleCache {
				detail = "reconcile_unavailable"
			}
			w.emit(b, now, state, stale.Milliseconds(), detail)
			w.alerted[b.AgentID] = true
		} else if w.alerted[b.AgentID] {
			// 恢复也走 AGENT_OFFLINE 事件（同一事件类型，消费方只订阅一种），
			// Detail="heartbeat recovered" 且 StalenessMs=0 区分。PowerState 填
			// running：心跳本身直接证明了主机在运行（对账要回答的正是「是否
			// 关机」），是观测值不是猜测，也免得消费方处理空值。
			w.emit(b, now, powerRunning, 0, "heartbeat recovered")
			delete(w.alerted, b.AgentID)
		}
	}
}

// emit 构造 AGENT_OFFLINE 事件并走 ingest 同一投影入 sink。服务器生成事件
// seq=0（无 agent 单调序号）；CH 唯一键=ts+agent_id 足够区分。
func (w *Watchdog) emit(b ingest.Beat, now time.Time, powerState string, stalenessMs int64, detail string) {
	ev := &pb.Event{
		Header: &pb.EventHeader{
			AgentId:   b.AgentID,
			Hostname:  b.Hostname,
			TsMs:      uint64(now.UnixMilli()),
			EventType: pb.EventType_AGENT_OFFLINE,
		},
		Body: &pb.Event_AgentOffline{AgentOffline: &pb.AgentOfflineEvent{
			AgentId:         b.AgentID,
			Hostname:        b.Hostname,
			LastHeartbeatMs: b.LastMs,
			StalenessMs:     stalenessMs,
			PowerState:      powerState,
			Detail:          detail,
		}},
	}
	row, err := ingest.RowOf(ev)
	if err != nil {
		// 静态构造的事件序列化失败只可能是编程错误，记日志吞掉即可
		slog.Error("deadman event protojson failed", "agent_id", b.AgentID, "err", err)
		return
	}
	w.sink.Write(row)
}
