// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// 非 Linux 平台桩：procpoll 采集器扫 /proc（Linux 专属文件系统）。开发机
// （Windows）构建与测试走本文件，形态对齐 ebpf/lkm 桩。
package procpoll

import (
	"context"
	"errors"
	"time"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

var ErrUnsupported = errors.New("procpoll collector: linux only")

type Collector struct {
	events chan *pb.Event
}

func New(interval time.Duration) (*Collector, error) { return nil, ErrUnsupported }
func (c *Collector) Name() string                    { return "procpoll" }
func (c *Collector) Events() <-chan *pb.Event        { return c.events }
func (c *Collector) Run(ctx context.Context) error   { return ErrUnsupported }
func (c *Collector) Close()                          {}
