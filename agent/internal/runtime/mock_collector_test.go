// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

// mockCollector 是测试用采集器：投递 n 个带事件体的事件，emitted 在
// 投递完成后关闭；onClose 记录 Close 调用。不进生产路径。
type mockCollector struct {
	name    string
	n       int
	events  chan *pb.Event
	emitted chan struct{}
	onClose func()
}

func newMockCollector(name string, n int) *mockCollector {
	return &mockCollector{
		name:    name,
		n:       n,
		events:  make(chan *pb.Event, 1024),
		emitted: make(chan struct{}),
	}
}

func (m *mockCollector) Name() string { return m.name }

func (m *mockCollector) Run(ctx context.Context) error {
	defer close(m.events)
	defer close(m.emitted)
	for i := 0; i < m.n; i++ {
		ev := &pb.Event{
			Header: &pb.EventHeader{EventType: pb.EventType_EXECVE},
			Body:   &pb.Event_Exit{Exit: &pb.ExitEvent{Pid: uint32(i)}},
		}
		select {
		case m.events <- ev:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (m *mockCollector) Events() <-chan *pb.Event { return m.events }

func (m *mockCollector) Close() {
	if m.onClose != nil {
		m.onClose()
	}
}
