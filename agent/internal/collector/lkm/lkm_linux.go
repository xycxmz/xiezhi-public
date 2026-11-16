// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package lkm 是 LKM 采集器（M1-B）：按内核版本加载 xiezhi_driver-<release>.ko，
// 读 /proc/xiezhi/endpoint 帧流并转为 proto 事件。数据结构与 driver/include/xiezhi_frame.h
// 严格镜像（显式 pad），改一处必须同步 C 侧与 eBPF 线。
package lkm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

const (
	kindExec   = 2
	kindConn   = 4
	kindDNS    = 5
	kindMprot  = 6
	kindMemfd  = 7
	kindModLd  = 8
	kindCred   = 9
	kindPtrace = 10
	kindSetsid = 11
	kindPrctl  = 12
	kindFile   = 13
	kindUmodH  = 14

	procEndpoint  = "/proc/xiezhi/endpoint"
	readChunk     = 8192
	pollTimeoutMs = 1000
	chanBuffer    = 4096

	frameHdrLen = 4
	frameMinLen = 6    // 帧契约：总长（含 4 字节长度字段本身）下界
	frameMaxLen = 1024 // 帧契约：总长上界，超出视为流损坏
)

// C 结构镜像（小端，自然对齐）。ev_connect/ev_dns 尾部 4 字节是 C 侧结构体
// 对齐垫，必须镜像否则 binary.Read 少读 4 字节。
type evHdr struct {
	Kind, Pid, Ppid, Pad uint32
	TsNs                 uint64
}

type evExec struct {
	H            evHdr
	Comm         [16]byte
	Filename     [128]byte
	Argv         [256]byte
	ArgvLen, UID uint32
	StartTicks   uint64
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

// evGeneric：MPROT/MEMFD/MOD_LOAD/CRED/PTRACE/SETSID/PRCTL 共用（detail 按 kind 语义见 xiezhi_frame.h）
type evGeneric struct {
	H      evHdr
	Detail uint64
}

// evFile：FILE_OPEN/UMOD_HELPER 共用（filename+flags）
type evFile struct {
	H        evHdr
	Filename [128]byte
	Flags    uint32
	Pad      uint32
}

// frameSizes 是帧形状的唯一真相源：kind -> 结构定长（不含 4 字节长度前缀）。
// 总长 != 定长+4 的帧按损坏丢弃。
var frameSizes = map[uint32]int{
	kindExec:   binary.Size(evExec{}),
	kindConn:   binary.Size(evConnect{}),
	kindDNS:    binary.Size(evDns{}),
	kindMprot:  binary.Size(evGeneric{}),
	kindMemfd:  binary.Size(evGeneric{}),
	kindModLd:  binary.Size(evGeneric{}),
	kindCred:   binary.Size(evGeneric{}),
	kindPtrace: binary.Size(evGeneric{}),
	kindSetsid: binary.Size(evGeneric{}),
	kindPrctl:  binary.Size(evGeneric{}),
	kindFile:   binary.Size(evFile{}),
	kindUmodH:  binary.Size(evFile{}),
}

// frameParser 是帧流累积解析器：feed 喂入每次 read 到的字节，返回新收全的
// 完整帧事件。帧可跨 read 边界（等待收全）；长度非法或与 kind 定长不符只丢
// 帧计数，不中断流。
type frameParser struct {
	buf       []byte
	corrupted uint64
}

func (p *frameParser) feed(chunk []byte) []*pb.Event {
	p.buf = append(p.buf, chunk...)
	var events []*pb.Event
	for len(p.buf) >= frameHdrLen {
		total := binary.LittleEndian.Uint32(p.buf[:frameHdrLen])
		if total < frameMinLen || total > frameMaxLen {
			// 长度字段本身不可信，无法按它跳帧：丢掉这 4 字节重新同步
			p.buf = p.buf[frameHdrLen:]
			p.corrupted++
			continue
		}
		if uint32(len(p.buf)) < total {
			break // 帧未收全，留给下一段
		}
		shapeOK := false
		if total >= frameHdrLen+4 {
			if want, known := frameSizes[binary.LittleEndian.Uint32(p.buf[frameHdrLen:frameHdrLen+4])]; known && int(total) == want+frameHdrLen {
				shapeOK = true
			}
		}
		if shapeOK {
			if ev := decodeFrame(p.buf[frameHdrLen:total]); ev != nil {
				events = append(events, ev)
			}
		} else {
			p.corrupted++
		}
		p.buf = p.buf[total:]
	}
	return events
}

// decodeFrame 解码一帧已通过形状校验的定长结构。
func decodeFrame(frame []byte) *pb.Event {
	r := bytes.NewReader(frame)
	switch binary.LittleEndian.Uint32(frame[:4]) {
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
	case kindDNS:
		var e evDns
		if binary.Read(r, binary.LittleEndian, &e) != nil {
			return nil
		}
		return dnsEvent(e)
	case kindMprot:
		var e evGeneric
		if binary.Read(r, binary.LittleEndian, &e) != nil {
			return nil
		}
		return genericEvent(pb.EventType_MPROT_EXEC, e)
	case kindMemfd:
		var e evGeneric
		if binary.Read(r, binary.LittleEndian, &e) != nil {
			return nil
		}
		return memExecEvent(e)
	case kindModLd:
		var e evGeneric
		if binary.Read(r, binary.LittleEndian, &e) != nil {
			return nil
		}
		return genericEvent(pb.EventType_MODULE_LOAD, e)
	case kindCred:
		var e evGeneric
		if binary.Read(r, binary.LittleEndian, &e) != nil {
			return nil
		}
		return credEvent(e)
	case kindPtrace:
		var e evGeneric
		if binary.Read(r, binary.LittleEndian, &e) != nil {
			return nil
		}
		return ptraceEvent(e)
	case kindSetsid:
		var e evGeneric
		if binary.Read(r, binary.LittleEndian, &e) != nil {
			return nil
		}
		return genericEvent(pb.EventType_SETSID, e)
	case kindPrctl:
		var e evGeneric
		if binary.Read(r, binary.LittleEndian, &e) != nil {
			return nil
		}
		return genericEvent(pb.EventType_PRCTL_NAME, e)
	case kindFile, kindUmodH:
		var e evFile
		if binary.Read(r, binary.LittleEndian, &e) != nil {
			return nil
		}
		return fileEvent(e)
	}
	return nil
}

// genericEvent 产共用帧（MPROT/MOD_LOAD/SETSID/PRCTL）的事件体，Detail 不丢。
func genericEvent(t pb.EventType, e evGeneric) *pb.Event {
	return &pb.Event{
		Header: &pb.EventHeader{EventType: t},
		Body: &pb.Event_Misc{Misc: &pb.MiscProcessEvent{
			Proc:   procCtx(e.H),
			Kind:   t.String(),
			Value:  fmt.Sprintf("detail=%d", e.Detail),
		}},
	}
}

func memExecEvent(e evGeneric) *pb.Event {
	return &pb.Event{
		Header: &pb.EventHeader{EventType: pb.EventType_MEMFD_CREATE},
		Body: &pb.Event_MemExec{MemExec: &pb.MemExecEvent{
			Proc:  procCtx(e.H),
			Kind:  "memfd_create",
			FdPath: fmt.Sprintf("flags=%d", e.Detail),
		}},
	}
}

func credEvent(e evGeneric) *pb.Event {
	old := uint32(e.Detail >> 32)
	new := uint32(e.Detail & 0xffffffff)
	return &pb.Event{
		Header: &pb.EventHeader{EventType: pb.EventType_CRED_CHANGE},
		Body: &pb.Event_Cred{Cred: &pb.CredEvent{
			Pid:    e.H.Pid,
			OldUid: old,
			NewUid: new,
			Exe:    "",
		}},
	}
}

func ptraceEvent(e evGeneric) *pb.Event {
	return &pb.Event{
		Header: &pb.EventHeader{EventType: pb.EventType_PTRACE},
		Body: &pb.Event_Ptrace{Ptrace: &pb.PtraceEvent{
			Tracer:    procCtx(e.H),
			TargetPid: 0,
			Request:   fmt.Sprintf("0x%x", e.Detail),
		}},
	}
}

// procCtx 从帧头建最小 ProcessContext（无 argv/uid 的共用帧用）。
func procCtx(h evHdr) *pb.ProcessContext {
	return &pb.ProcessContext{Pid: h.Pid, Ppid: h.Ppid}
}

func fileEvent(e evFile) *pb.Event {
	name := cstr(e.Filename[:])
	return &pb.Event{
		Header: &pb.EventHeader{EventType: pb.EventType_FILE_OPEN},
		Body: &pb.Event_File{File: &pb.FileEvent{
			Proc: procCtx(e.H),
			Op:   "open",
			File: &pb.FileRef{Path: name},
		}},
	}
}

func execEvent(e evExec) *pb.Event {
	proc := &pb.ProcessContext{Pid: e.H.Pid, Ppid: e.H.Ppid, Uid: e.UID, StartTicks: e.StartTicks}
	proc.Exe = cstr(e.Filename[:])
	if proc.Exe == "" {
		proc.Exe = cstr(e.Comm[:]) // 取用户串失败时的兜底，与 eBPF 线一致
	}
	if e.ArgvLen > 0 && int64(e.ArgvLen) <= int64(len(e.Argv)) {
		for _, part := range bytes.Split(e.Argv[:e.ArgvLen], []byte{0}) {
			if len(part) > 0 {
				proc.Argv = append(proc.Argv, cstr(part))
			}
		}
	}
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
	return &pb.Event{
		Header: &pb.EventHeader{EventType: pb.EventType_CONNECT},
		Body: &pb.Event_Net{Net: &pb.NetEvent{
			Proc:   &pb.ProcessContext{Pid: e.H.Pid, Ppid: e.H.Ppid},
			Op:     "connect",
			Ip:     append([]byte(nil), e.IP[:ipLen]...),
			Port:   uint32(e.Port),
			Family: fam,
		}},
	}
}

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
			// Queries 留空：M2 用户态从抓包/缓存补域名，内核只给 server 元组
		}},
	}
}

// cstr 取 NUL 截断的 C 字符串并清洗为合法 UTF-8（内核抓的是用户内存原文，
// proto3 string 字段要求 UTF-8，否则 gRPC marshal 直接拒批）。
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.ToValidUTF8(strings.TrimSpace(string(b)), "�")
}

// Collector 实现 collector.Collector：加载驱动、读 /proc 帧流、投递事件。
type Collector struct {
	events chan *pb.Event
	log    *slog.Logger
	mgr    *manager

	// 接缝（默认指向真实实现，测试注入假件）
	openData     func() (*os.File, error)
	ensureLoaded func(ctx context.Context) (retryAfter time.Duration, err error)
}

// New 按 koDir 与当前内核版本（uname -r）精确匹配 xiezhi_driver-<release>.ko。
// 无匹配 ko 时返回明确错误，调用方应降级为心跳模式。
func New(koDir string) (*Collector, error) {
	release := kernelRelease()
	if release == "" {
		return nil, errors.New("lkm: uname failed")
	}
	log := slog.With("collector", "lkm")
	mgr, err := newManager(koDir, release, log)
	if err != nil {
		return nil, err
	}
	c := &Collector{
		events: make(chan *pb.Event, chanBuffer),
		log:    log,
		mgr:    mgr,
	}
	c.openData = func() (*os.File, error) { return os.Open(procEndpoint) }
	c.ensureLoaded = mgr.ensureLoaded
	return c, nil
}

func (c *Collector) Name() string             { return "lkm" }
func (c *Collector) Events() <-chan *pb.Event { return c.events }

// Run 阻塞运行：驱动加载循环（退避重试）→ /proc 读循环；读面失败先卸载再
// 重走加载循环。ctx 取消后关闭事件通道并返回。
func (c *Collector) Run(ctx context.Context) error {
	defer close(c.events)
	for {
		delay, err := c.ensureLoaded(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			c.log.Warn("driver load failed, retry scheduled", "err", err, "retry_in", delay)
			if sleepCtx(ctx, delay) != nil {
				return nil
			}
			continue
		}
		if rerr := c.readLoop(ctx); rerr != nil {
			if ctx.Err() != nil {
				return nil
			}
			c.log.Warn("driver data plane failed, reloading", "err", rerr)
			if c.mgr != nil {
				c.mgr.unload()
			}
			continue
		}
		return nil
	}
}

// readLoop 是数据面：poll(1s) 心跳轮驱动 read(8KB)，帧跨 read 边界由
// frameParser 累积。返回非 nil 错误表示数据面异常（调用方重走加载循环）。
func (c *Collector) readLoop(ctx context.Context) error {
	f, err := c.openData()
	if err != nil {
		return fmt.Errorf("open %s: %w", procEndpoint, err)
	}
	defer f.Close()

	var parser frameParser
	buf := make([]byte, readChunk)
	fds := []unix.PollFd{{Fd: int32(f.Fd()), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(fds, pollTimeoutMs)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("poll: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if n == 0 {
			continue // 超时是常态：心跳轮
		}
		rev := fds[0].Revents
		if rev&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return fmt.Errorf("poll endpoint: revents=%#04x", rev)
		}
		if rev&unix.POLLIN == 0 {
			continue
		}
		nr, rerr := f.Read(buf)
		if rerr != nil {
			if errors.Is(rerr, unix.EINTR) {
				continue
			}
			return fmt.Errorf("read endpoint: %w", rerr)
		}
		if nr == 0 {
			// POLLIN 后读到 0 = 驱动侧环形游标卡死，重走加载循环自愈
			return errors.New("endpoint readable but returned no data")
		}
		for _, ev := range parser.feed(buf[:nr]) {
			select {
			case c.events <- ev:
			case <-ctx.Done():
				return nil
			}
		}
		if parser.corrupted > 0 && (parser.corrupted == 1 || parser.corrupted%1000 == 0) {
			c.log.Warn("frame stream corrupted, frames dropped", "total", parser.corrupted)
		}
	}
}

// Close 卸载驱动。rmmod 失败只记日志（下次 ensureLoaded 会重新收敛）。
func (c *Collector) Close() {
	if c.mgr != nil {
		c.mgr.unload()
	}
}
