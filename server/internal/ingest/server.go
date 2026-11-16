// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"io"
	"log/slog"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/xycxmz/xiezhi-public/proto"
	"github.com/xycxmz/xiezhi-public/server/internal/pipeline"
	"github.com/xycxmz/xiezhi-public/server/internal/store"
)

// Sink 消费已去重的存储行（真实现为 sink.DualWrite，测试为 fake）。
type Sink interface {
	Write(row store.Row)
}

// Server 实现 pb.IngestServer。
type Server struct {
	pb.UnimplementedIngestServer
	window  *seqWindow
	sink    Sink
	beats   *Heartbeats
	pipe    pipeline.PipelineLike // M3 检测链（nil=未装配，事件只走 sink）
	version string
}

func NewServer(sink Sink, beats *Heartbeats, version string, windowCapacity int) *Server {
	if beats == nil {
		beats = NewHeartbeats()
	}
	return &Server{window: newSeqWindow(windowCapacity), sink: sink, beats: beats, version: version}
}

// SetPipeline 注入检测链（构造后、Serve 前调用一次）。
func (s *Server) SetPipeline(p pipeline.PipelineLike) { s.pipe = p }

// Stream 逐批处理直到客户端半关闭；单事件级失败只跳过该事件不断流。
func (s *Server) Stream(stream pb.Ingest_StreamServer) error {
	var accepted uint64
	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.StreamSummary{Accepted: accepted, ServerVersion: s.version})
		}
		if err != nil {
			return err
		}
		if batch == nil {
			continue
		}
		for _, ev := range batch.Events {
			row, ok := s.accept(ev)
			if !ok {
				continue
			}
			s.sink.Write(row)
			accepted++
		}
	}
}

func (s *Server) accept(ev *pb.Event) (store.Row, bool) {
	h := ev.GetHeader()
	if ev == nil || h == nil {
		return store.Row{}, false
	}
	if s.window.Seen(h.GetAgentId(), h.GetSeq()) {
		return store.Row{}, false
	}
	row, err := RowOf(ev)
	if err != nil {
		slog.Warn("event dropped, protojson failed", "agent_id", h.GetAgentId(), "seq", h.GetSeq(), "err", err)
		return store.Row{}, false
	}
	if h.GetEventType() == pb.EventType_AGENT_HEARTBEAT {
		s.beats.Record(h.GetAgentId(), h.GetHostname(), ev.GetHeartbeat().GetInstanceId(), row.Ts.UnixMilli())
	}
	// M3：去重后进 sink 前交给检测链（规则/first-seen/session）。
	// pipeline 可能nil（老配置启动），handler 侧自保非阻塞。
	if s.pipe != nil {
		s.pipe.Process(context.Background(), ev)
	}
	return row, true
}

// RowOf 是事件→存储行投影；dead-man 看门狗产服务器侧事件时复用同一路。
func RowOf(ev *pb.Event) (store.Row, error) {
	body, err := protojson.Marshal(ev)
	if err != nil {
		return store.Row{}, err
	}
	h := ev.GetHeader()
	// ts_ms=0 视为缺时钟：以接收时刻入库，保证事件可查而非静默丢失
	ts := time.Now()
	if h.GetTsMs() > 0 {
		ts = time.UnixMilli(int64(h.GetTsMs()))
	}
	return store.Row{
		Ts:        ts,
		AgentID:   h.GetAgentId(),
		Hostname:  h.GetHostname(),
		EventType: h.GetEventType().String(),
		Body:      string(body),
	}, nil
}
