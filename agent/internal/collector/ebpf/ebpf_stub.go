// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// 非 Linux 平台桩：eBPF 采集器仅支持 Linux（cilium/ebpf 的 kprobe/tracepoint/ringbuf
// 均带 linux 构建约束）。开发机（Windows）构建与测试走本文件。
package ebpf

import (
	"context"
	"errors"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

var ErrUnsupported = errors.New("ebpf collector: linux only")

type Collector struct {
	events chan *pb.Event
}

func New() (*Collector, error)                     { return nil, ErrUnsupported }
func (c *Collector) Name() string                  { return "ebpf" }
func (c *Collector) Events() <-chan *pb.Event      { return c.events }
func (c *Collector) Run(ctx context.Context) error { return ErrUnsupported }
func (c *Collector) Close()                        {}
