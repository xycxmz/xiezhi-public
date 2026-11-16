// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// 非 Linux 平台桩：journal 采集器读 Linux 认证日志（inode/Stat_t 轮转检测
// 是 Linux 专属）。开发机（Windows）构建与测试走本文件，形态对齐 ebpf/lkm 桩。
package journal

import (
	"context"
	"errors"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

var ErrUnsupported = errors.New("journal collector: linux only")

type Collector struct {
	events chan *pb.Event
}

func New(path string) (*Collector, error)          { return nil, ErrUnsupported }
func (c *Collector) Name() string                  { return "journal" }
func (c *Collector) Events() <-chan *pb.Event      { return c.events }
func (c *Collector) Run(ctx context.Context) error { return ErrUnsupported }
func (c *Collector) Close()                        {}
