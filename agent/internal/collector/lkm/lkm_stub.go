// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// 非 Linux 平台桩：LKM 采集器仅支持 Linux（syscall.Poll/Uname/insmod 均是
// Linux 专属）。开发机（Windows）构建走本文件。
package lkm

import (
	"context"
	"errors"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

var ErrUnsupported = errors.New("lkm collector: linux only")

type Collector struct {
	events chan *pb.Event
}

func New(koDir string) (*Collector, error)    { return nil, ErrUnsupported }
func (c *Collector) Name() string             { return "lkm" }
func (c *Collector) Events() <-chan *pb.Event { return c.events }
func (c *Collector) Run(ctx context.Context) error {
	return ErrUnsupported
}
func (c *Collector) Close() {}
