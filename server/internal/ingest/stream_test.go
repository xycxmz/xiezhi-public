// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/xycxmz/xiezhi-public/proto"
	"github.com/xycxmz/xiezhi-public/server/internal/store"
)

type fakeSink struct{ rows []store.Row }

func (f *fakeSink) Write(r store.Row) { f.rows = append(f.rows, r) }

func ev(agent string, seq uint64, tsMs uint64) *pb.Event {
	return &pb.Event{
		Header: &pb.EventHeader{
			AgentId:   agent,
			Hostname:  "h1",
			TsMs:      tsMs,
			Seq:       seq,
			EventType: pb.EventType_EXECVE,
		},
		Body: &pb.Event_Heartbeat{Heartbeat: &pb.HeartbeatEvent{AgentVersion: "t"}},
	}
}

func TestStreamDedupAndSummary(t *testing.T) {
	sink := &fakeSink{}
	lis := bufconn.Listen(64 * 1024)
	gs := grpc.NewServer()
	pb.RegisterIngestServer(gs, NewServer(sink, NewHeartbeats(), "test", 8192))
	go gs.Serve(lis)
	defer gs.Stop()

	dial := func(context.Context, string) (net.Conn, error) { return lis.DialContext(context.Background()) }
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(dial),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	stream, err := pb.NewIngestClient(conn).Stream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mustSend := func(events ...*pb.Event) {
		if err := stream.Send(&pb.EventBatch{Events: events}); err != nil {
			t.Fatal(err)
		}
	}
	mustSend(ev("a", 1, 1000), ev("a", 2, 1000))
	mustSend(ev("a", 2, 1000), ev("a", 3, 1000)) // seq 2 重放，须被窗口滤掉
	mustSend(ev("b", 2, 1000))                   // 另一 agent 同 seq 不算重放
	mustSend(nil, &pb.Event{})                   // nil 与缺头事件不断流、不计数
	summary, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatal(err)
	}
	if summary.Accepted != 4 {
		t.Fatalf("accepted = %d, want 4", summary.Accepted)
	}
	if summary.ServerVersion != "test" {
		t.Fatalf("server_version = %q, want %q", summary.ServerVersion, "test")
	}
	if len(sink.rows) != 4 {
		t.Fatalf("sink rows = %d, want 4", len(sink.rows))
	}
	first := sink.rows[0]
	if first.AgentID != "a" || first.Hostname != "h1" || first.EventType != "EXECVE" {
		t.Fatalf("row projection wrong: %+v", first)
	}
	if got := first.Ts.UnixMilli(); got != 1000 {
		t.Fatalf("ts = %d ms, want 1000", got)
	}
	if !strings.Contains(first.Body, `"agentId":"a"`) || !strings.Contains(first.Body, `"eventType":"EXECVE"`) {
		t.Fatalf("body is not protojson of the full event: %s", first.Body)
	}
}

func TestToRowTsFallbackOnZero(t *testing.T) {
	row, err := RowOf(ev("a", 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if row.Ts.After(now) || row.Ts.Before(now.Add(-time.Minute)) {
		t.Fatalf("ts fallback = %v, want receive time", row.Ts)
	}
}

func TestHeartbeatRecordedOnIngest(t *testing.T) {
	beats := NewHeartbeats()
	sink := &fakeSink{}
	lis := bufconn.Listen(64 * 1024)
	gs := grpc.NewServer()
	pb.RegisterIngestServer(gs, NewServer(sink, beats, "test", 8192))
	go gs.Serve(lis)
	defer gs.Stop()

	dial := func(context.Context, string) (net.Conn, error) { return lis.DialContext(context.Background()) }
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(dial),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	stream, err := pb.NewIngestClient(conn).Stream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// ts_ms=0 的心跳必须落成接收时刻，否则该 agent 在 deadman 视角永远陈旧
	hb := ev("hb-agent", 1, 0)
	hb.Header.EventType = pb.EventType_AGENT_HEARTBEAT
	if err := stream.Send(&pb.EventBatch{Events: []*pb.Event{hb}}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.CloseAndRecv(); err != nil {
		t.Fatal(err)
	}
	b, ok := beats.Last("hb-agent")
	if !ok {
		t.Fatal("heartbeat not recorded")
	}
	if b.Hostname != "h1" {
		t.Fatalf("hostname = %q, want h1", b.Hostname)
	}
	if d := time.Since(time.UnixMilli(b.LastMs)); d < 0 || d > time.Minute {
		t.Fatalf("last_ms = %d (%v ago), want receive time", b.LastMs, d)
	}
}
