// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package ebpf 是 eBPF 采集器（M1-A）：加载内嵌 events.bpf.o，挂 fork/exec/exit/connect
// 四个探针，ringbuf 读取并转为 proto 事件。数据结构与 bpf/events.bpf.c 的 C 定义
// 严格镜像（显式 pad），改一处必须同步另一处。
package ebpf

import (
	"bytes"
	"context"
	_ "embed"
	"os"
	"encoding/binary"
	"fmt"
	"errors"
	"log/slog"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

//go:embed events.bpf.o
var objBytes []byte

const (
	kindFork   = 1
	kindExec   = 2
	kindExit   = 3
	kindConn   = 4
	kindDns    = 5
	chanBuffer = 4096
)

// C 结构镜像（小端，自然对齐；ev_connect 尾部 4 字节对齐垫）。
type evHdr struct {
	Kind, Pid, Ppid, Pad uint32
	TsNs                 uint64
}

type evFork struct {
	H              evHdr
	ChildPid, Pad2 uint32
	ChildStart     uint64
}

type evExec struct {
	H            evHdr
	Comm         [16]byte
	Filename     [128]byte
	Argv         [256]byte
	ArgvLen, UID uint32
	StartTicks   uint64
}

type evExit struct {
	H          evHdr
	Code, Pad2 uint32
}

type evConnect struct {
	H            evHdr
	Family, Pad1 uint8
	Port         uint16
	IP           [16]byte
	Tail         [4]byte
}

type evDns struct {
	H            evHdr
	Family, Pad1 uint8
	Port         uint16
	IP           [16]byte
	Tail         [4]byte
}

type Collector struct {
	events chan *pb.Event
	coll   *ebpf.Collection
	links  []link.Link
	rd     *ringbuf.Reader
	log    *slog.Logger
}

func New() (*Collector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		// 5.11+ 走 memcg 记账，此处失败不致命
		slog.Warn("rlimit.RemoveMemlock failed", "err", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objBytes))
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}
	c := &Collector{
		events: make(chan *pb.Event, chanBuffer),
		coll:   coll,
		log:    slog.With("collector", "ebpf"),
	}

	tps := []struct{ section, prog, tp string }{
		{"raw_tp_fork", "on_fork", "sched_process_fork"},
		{"raw_tp_exec", "on_exec", "sched_process_exec"},
		{"raw_tp_exit", "on_exit", "sched_process_exit"},
	}
	for _, t := range tps {
		prog := coll.Programs[t.prog]
		if prog == nil {
			coll.Close()
			return nil, fmt.Errorf("program %s missing", t.prog)
		}
		lk, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: t.tp, Program: prog})
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("attach %s: %w", t.section, err)
		}
		c.links = append(c.links, lk)
	}

	// kprobe 失败降级（老/裁剪内核可能无该符号），采集面缺失要大声说但不致命
	for _, kp := range []struct{ symbol, prog string }{
		{"security_socket_connect", "on_connect"},
		{"udp_sendmsg", "on_dns"},
	} {
		if prog := coll.Programs[kp.prog]; prog != nil {
			if lk, err := link.Kprobe(kp.symbol, prog, nil); err != nil {
				c.log.Warn("attach failed, running without this event kind",
					"symbol", kp.symbol, "err", err)
			} else {
				c.links = append(c.links, lk)
			}
		}
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	c.rd = rd
	return c, nil
}

func (c *Collector) Name() string             { return "ebpf" }
func (c *Collector) Events() <-chan *pb.Event { return c.events }

func (c *Collector) Run(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		c.rd.Close() // 令阻塞 Read 返回 ringbuf.ErrClosed
		close(done)
	}()
	defer func() { <-done }()

	for {
		rec, err := c.rd.Read()
		if err != nil {
			// Close() 与阻塞 Read 并发时可能返回包装过的 closed 错误
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				close(c.events)
				return nil
			}
			c.log.Warn("ringbuf read", "err", err)
			continue
		}
		if ev := decode(rec.RawSample); ev != nil {
			select {
			case c.events <- ev:
			case <-ctx.Done():
				close(c.events)
				return nil
			}
		}
	}
}

func decode(b []byte) *pb.Event {
	if len(b) < 8 {
		return nil
	}
	var h evHdr
	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &h); err != nil {
		return nil
	}
	r := bytes.NewReader(b)
	switch h.Kind {
	case kindExec:
		var e evExec
		if binary.Read(r, binary.LittleEndian, &e) != nil {
			return nil
		}
		return execEvent(e)
	case kindConn:
		var e evConnect
		if binary.Read(r, binary.LittleEndian, &e) != nil {
			return nil
		}
		return connEvent(e)
	case kindDns:
		var e evDns
		if binary.Read(r, binary.LittleEndian, &e) != nil {
			return nil
		}
		return dnsEvent(e)
	case kindFork:
		var e evFork
		if binary.Read(r, binary.LittleEndian, &e) != nil {
			return nil
		}
		return &pb.Event{
			Header: &pb.EventHeader{EventType: pb.EventType_FORK},
			Body: &pb.Event_Fork{Fork: &pb.ForkEvent{
				Parent:          procCtx(e.H, nil),
				ChildPid:        e.ChildPid,
				ChildStartTicks: e.ChildStart,
			}},
		}
	case kindExit:
		var e evExit
		if binary.Read(r, binary.LittleEndian, &e) != nil {
			return nil
		}
		return &pb.Event{
			Header: &pb.EventHeader{EventType: pb.EventType_EXIT},
			Body: &pb.Event_Exit{Exit: &pb.ExitEvent{
				Pid:  e.H.Pid,
				Code: int32(e.Code),
			}},
		}
	}
	return nil
}

func execEvent(e evExec) *pb.Event {
	proc := procCtx(e.H, &e.Comm)
	proc.Exe = cstr(e.Filename[:])
	if proc.Exe == "" {
		proc.Exe = cstr(e.Comm[:])
	}
	proc.Uid = e.UID
	proc.StartTicks = e.StartTicks
	if e.ArgvLen > 0 && int(e.ArgvLen) <= len(e.Argv) {
		raw := e.Argv[:e.ArgvLen]
		for _, part := range bytes.Split(raw, []byte{0}) {
			if len(part) > 0 {
				proc.Argv = append(proc.Argv, cstr(part))
			}
		}
	}
	// cwd/env 富化在用户态按需读 /proc；短命进程会 miss，内核已带 argv 原文兜底
	return &pb.Event{
		Header: &pb.EventHeader{EventType: pb.EventType_EXECVE},
		Body:   &pb.Event_Execve{Execve: &pb.ExecveEvent{Proc: proc}},
	}
}

func connEvent(e evConnect) *pb.Event {
	fam := "ip6"
	ipLen := 16
	if e.Family == 4 {
		fam = "ip4"
		ipLen = 4
	}
	proc := &pb.ProcessContext{Pid: e.H.Pid, Ppid: e.H.Ppid}
	return &pb.Event{
		Header: &pb.EventHeader{EventType: pb.EventType_CONNECT},
		Body: &pb.Event_Net{Net: &pb.NetEvent{
			Proc:    proc,
			Op:      "connect",
			Ip:      append([]byte(nil), e.IP[:ipLen]...),
			Port:    uint32(e.Port),
			Family:  fam,
		}},
	}
}

// dnsEvent 只记查询目标（服务器 ip/port），域名解析在 M2 用户态补
// （SecEBL 语料/隧道检测需要域名）。
func dnsEvent(e evDns) *pb.Event {
	ipLen := 16
	if e.Family == 4 {
		ipLen = 4
	}
	return &pb.Event{
		Header: &pb.EventHeader{EventType: pb.EventType_DNS_QUERY},
		Body: &pb.Event_Dns{Dns: &pb.DnsEvent{
			Proc:       &pb.ProcessContext{Pid: e.H.Pid, Ppid: e.H.Ppid},
			ServerIp:   net.IP(e.IP[:ipLen]).String(),
			ServerPort: uint32(e.Port),
		}},
	}
}

func procCtx(h evHdr, comm *[16]byte) *pb.ProcessContext {
	p := &pb.ProcessContext{Pid: h.Pid, Ppid: h.Ppid}
	if comm != nil {
		p.Tty = "" // M2: /proc/<pid>/fd/0
	}
	return p
}

// cstr 取 NUL 截断的 C 字符串并清洗为合法 UTF-8（内核抓的是用户内存原文，
// proto3 string 字段要求 UTF-8，否则 gRPC marshal 直接拒批）。
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.ToValidUTF8(strings.TrimSpace(string(b)), "\uFFFD")
}

func (c *Collector) Close() {
	if c.rd != nil {
		c.rd.Close()
	}
	for _, lk := range c.links {
		lk.Close()
	}
	if c.coll != nil {
		c.coll.Close()
	}
}
