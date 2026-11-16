// SPDX-License-Identifier: Apache-2.0

package deadman

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/xycxmz/xiezhi-public/proto"
	"github.com/xycxmz/xiezhi-public/server/internal/ingest"
	"github.com/xycxmz/xiezhi-public/server/internal/store"
)

type fakeSink struct{ rows []store.Row }

func (f *fakeSink) Write(r store.Row) { f.rows = append(f.rows, r) }

func (f *fakeSink) offlineEvents(t *testing.T) []*pb.AgentOfflineEvent {
	t.Helper()
	var out []*pb.AgentOfflineEvent
	for _, r := range f.rows {
		if r.EventType != "AGENT_OFFLINE" {
			t.Fatalf("unexpected event type %q", r.EventType)
		}
		ev := &pb.Event{}
		if err := protojson.Unmarshal([]byte(r.Body), ev); err != nil {
			t.Fatalf("body not valid protojson: %v", err)
		}
		off := ev.GetAgentOffline()
		if off == nil {
			t.Fatalf("body is not agent_offline: %s", r.Body)
		}
		if ev.GetHeader().GetEventType() != pb.EventType_AGENT_OFFLINE || ev.GetHeader().GetSeq() != 0 {
			t.Fatalf("header wrong: %s", r.Body)
		}
		out = append(out, off)
	}
	return out
}

func newWatchdog(src instanceSource, threshold time.Duration) (*Watchdog, *ingest.Heartbeats, *fakeSink) {
	beats := ingest.NewHeartbeats()
	sink := &fakeSink{}
	recon := NewReconciler(src)
	return New(beats, sink, recon, threshold, 30*time.Second), beats, sink
}

func TestWatchdogSuppressesPoweredOff(t *testing.T) {
	wd, beats, sink := newWatchdog(&fakeSource{insts: []sasInstance{
		{Uuid: "agent-off", Status: "notRunning", ClientStatus: "offline"},
	}}, time.Minute)
	now := time.Now()
	beats.Record("agent-off", "host-off", "", now.Add(-10*time.Minute).UnixMilli())

	wd.scanOnce(context.Background(), now)
	wd.scanOnce(context.Background(), now.Add(time.Second))
	if got := len(sink.rows); got != 0 {
		t.Fatalf("powered-off machine alerted: %d events", got)
	}
}

func TestWatchdogAlertsRunningAndNotFound(t *testing.T) {
	wd, beats, sink := newWatchdog(&fakeSource{insts: []sasInstance{
		{Uuid: "agent-r", Status: "running"},
		{Uuid: "someone-else", Status: "notRunning"}, // 本 agent 在 SAS 查无此机
	}}, time.Minute)
	now := time.Now()
	staleMs := now.Add(-10 * time.Minute).UnixMilli()
	beats.Record("agent-r", "host-r", "", staleMs)
	beats.Record("agent-unseen", "host-u", "", staleMs)

	wd.scanOnce(context.Background(), now)
	evs := sink.offlineEvents(t)
	if len(evs) != 2 {
		t.Fatalf("events = %d, want 2 (running + not_found)", len(evs))
	}
	byAgent := map[string]*pb.AgentOfflineEvent{}
	for _, e := range evs {
		byAgent[e.AgentId] = e
	}
	r := byAgent["agent-r"]
	if r.PowerState != powerRunning || r.Hostname != "host-r" ||
		r.LastHeartbeatMs != staleMs || r.StalenessMs != 10*time.Minute.Milliseconds() || r.Detail != "" {
		t.Fatalf("running-agent event wrong: %+v", r)
	}
	if u := byAgent["agent-unseen"]; u.PowerState != powerNotFound {
		t.Fatalf("unmatched agent power_state = %q, want not_found", u.PowerState)
	}

	// 同一 agent 未恢复（再次收到心跳）前不重复告警
	wd.scanOnce(context.Background(), now.Add(30*time.Second))
	if got := len(sink.rows); got != 2 {
		t.Fatalf("repeat alerts not suppressed: %d events", got)
	}
}

func TestWatchdogAlertsWithoutReconcile(t *testing.T) {
	wd, beats, sink := newWatchdog(nil, time.Minute)
	now := time.Now()
	beats.Record("agent-x", "host-x", "", now.Add(-10*time.Minute).UnixMilli())
	wd.scanOnce(context.Background(), now)
	evs := sink.offlineEvents(t)
	if len(evs) != 1 || evs[0].PowerState != powerNotFound {
		t.Fatalf("nil reconcile must alert not_found: %+v", evs)
	}
}

func TestWatchdogAmbiguousPowerAlerts(t *testing.T) {
	// UNKNOWN + aegis online：云侧没说关机，dead-man 偏好告警
	wd, beats, sink := newWatchdog(&fakeSource{insts: []sasInstance{
		{Uuid: "agent-q", Status: "UNKNOWN", ClientStatus: "online"},
	}}, time.Minute)
	now := time.Now()
	beats.Record("agent-q", "host-q", "", now.Add(-10*time.Minute).UnixMilli())
	wd.scanOnce(context.Background(), now)
	evs := sink.offlineEvents(t)
	if len(evs) != 1 || evs[0].PowerState != powerUnknown {
		t.Fatalf("ambiguous power must alert as unknown: %+v", evs)
	}
}

func TestWatchdogFreshAgentSilent(t *testing.T) {
	wd, beats, sink := newWatchdog(nil, time.Minute)
	now := time.Now()
	beats.Record("agent-f", "host-f", "", now.Add(-10*time.Second).UnixMilli())
	wd.scanOnce(context.Background(), now)
	if got := len(sink.rows); got != 0 {
		t.Fatalf("fresh agent produced %d events", got)
	}
}

func TestWatchdogRecoveryThenNoRepeat(t *testing.T) {
	wd, beats, sink := newWatchdog(nil, time.Minute)
	now := time.Now()
	beats.Record("agent-r", "host-r", "", now.Add(-10*time.Minute).UnixMilli())
	wd.scanOnce(context.Background(), now)
	if len(sink.rows) != 1 {
		t.Fatalf("alert missing: %d events", len(sink.rows))
	}

	fresh := now.Add(5 * time.Second)
	beats.Record("agent-r", "host-r", "", fresh.UnixMilli())
	wd.scanOnce(context.Background(), now.Add(6*time.Second))
	evs := sink.offlineEvents(t)
	if len(evs) != 2 {
		t.Fatalf("want alert+recovery, got %d", len(evs))
	}
	rec := evs[1]
	if rec.Detail != "heartbeat recovered" || rec.StalenessMs != 0 || rec.PowerState != powerRunning {
		t.Fatalf("recovery event wrong: %+v", rec)
	}
	wd.scanOnce(context.Background(), now.Add(7*time.Second))
	if got := len(sink.rows); got != 2 {
		t.Fatalf("recovery repeated: %d events", got)
	}

	// 第二轮失联（时间推进过阈值，非回拨时间戳）→ 必须能再告警
	wd.scanOnce(context.Background(), fresh.Add(2*time.Minute))
	if got := len(sink.rows); got != 3 {
		t.Fatalf("second outage must re-alert: %d events", got)
	}
}

func TestWatchdogSuppressedMachineRecoversSilently(t *testing.T) {
	wd, beats, sink := newWatchdog(&fakeSource{insts: []sasInstance{
		{Uuid: "agent-s", Status: "notRunning", ClientStatus: "offline"},
	}}, time.Minute)
	now := time.Now()
	beats.Record("agent-s", "host-s", "", now.Add(-10*time.Minute).UnixMilli())
	wd.scanOnce(context.Background(), now)
	beats.Record("agent-s", "host-s", "", now.Add(time.Second).UnixMilli())
	wd.scanOnce(context.Background(), now.Add(2*time.Second))
	// 从未告警 → 恢复也不发 recovery（否则产生无配对的恢复事件）
	if got := len(sink.rows); got != 0 {
		t.Fatalf("suppressed machine emitted %d events", got)
	}
}

// 扫描快照陈旧但 emit 前心跳到达（对账 10s 预算窗口内恢复）→ 不得误告警。
func TestWatchdogHeartbeatDuringReconcile(t *testing.T) {
	now := time.Now()
	wd, beats, sink := newWatchdog(&fakeSource{insts: []sasInstance{
		{Uuid: "agent-late", Status: "running"},
	}}, time.Minute)
	beats.Record("agent-late", "host-l", "", now.Add(-10*time.Minute).UnixMilli())
	wd.recon.src.(*fakeSource).hook = func() {
		beats.Record("agent-late", "host-l", "", now.Add(-time.Second).UnixMilli())
	}
	wd.scanOnce(context.Background(), now)
	if got := len(sink.rows); got != 0 {
		t.Fatalf("heartbeat-during-reconcile alerted: %d events", got)
	}
}

func TestWatchdogStaleCacheFlaggedInDetail(t *testing.T) {
	base := time.Now()
	src := &fakeSource{err: errors.New("sas unreachable")} // 首拉即败：无缓存可用
	recon := NewReconciler(src)
	recon.now = func() time.Time { return base }
	beats := ingest.NewHeartbeats()
	sink := &fakeSink{}
	wd := New(beats, sink, recon, time.Minute, 30*time.Second)
	beats.Record("agent-c", "host-c", "", base.Add(-10*time.Minute).UnixMilli())

	wd.scanOnce(context.Background(), base)
	evs := sink.offlineEvents(t)
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	if evs[0].PowerState != powerNotFound || evs[0].Detail != "reconcile_unavailable" {
		t.Fatalf("degraded reconcile must mark detail: %+v", evs[0])
	}
}
