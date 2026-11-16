// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lkm

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

func leBytes(t *testing.T, v any) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	return b.Bytes()
}

// frameOf 按帧契约构造 [u32 总长（含自身）][结构体]。
func frameOf(t *testing.T, v any) []byte {
	t.Helper()
	body := leBytes(t, v)
	out := make([]byte, frameHdrLen+len(body))
	binary.LittleEndian.PutUint32(out[:frameHdrLen], uint32(len(body)+frameHdrLen))
	copy(out[frameHdrLen:], body)
	return out
}

func testExecEv() evExec {
	e := evExec{}
	e.H = evHdr{Kind: kindExec, Pid: 4242, Ppid: 1, TsNs: 1234567890}
	copy(e.Comm[:], "curl")
	copy(e.Filename[:], "/usr/bin/curl")
	argv := "/usr/bin/curl\x00https://example.com\x00"
	copy(e.Argv[:], argv)
	e.ArgvLen = uint32(len(argv))
	e.UID = 1000
	return e
}

func testConnEv() evConnect {
	e := evConnect{}
	e.H = evHdr{Kind: kindConn, Pid: 77, Ppid: 4242, TsNs: 1}
	e.Family = 4
	e.Port = 443
	copy(e.IP[:4], net.ParseIP("8.8.8.8").To4())
	return e
}

func testDns6Ev() evDns {
	e := evDns{}
	e.H = evHdr{Kind: kindDNS, Pid: 78, Ppid: 4242, TsNs: 2}
	e.Family = 6
	e.Port = 53
	copy(e.IP[:], net.ParseIP("2001:db8::1").To16())
	return e
}

// 结构镜像必须与 C 侧 sizeof 逐字节一致（driver/include/xiezhi_frame.h），
// 改坏任何一处此测试先红。
func TestMirrorSizesMatchContract(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"hdr", binary.Size(evHdr{}), 24},
		{"exec", binary.Size(evExec{}), 440}, // v2: +StartTicks u64
		{"connect", binary.Size(evConnect{}), 48},
		{"dns", binary.Size(evDns{}), 48},
		{"generic", binary.Size(evGeneric{}), 32},
		{"file", binary.Size(evFile{}), 160},
	} {
		if tc.got != tc.want {
			t.Errorf("%s size = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
	for kind, want := range map[uint32]int{
		kindExec: 440, kindConn: 48, kindDNS: 48,
		kindMprot: 32, kindMemfd: 32, kindModLd: 32,
		kindCred: 32, kindPtrace: 32, kindSetsid: 32, kindPrctl: 32,
		kindFile: 160, kindUmodH: 160,
	} {
		if frameSizes[kind] != want {
			t.Errorf("frameSizes[%d] = %d, want %d", kind, frameSizes[kind], want)
		}
	}
}

func TestFrameDecodeRoundtrip(t *testing.T) {
	stream := bytes.Join([][]byte{
		frameOf(t, testExecEv()),
		frameOf(t, testConnEv()),
		frameOf(t, testDns6Ev()),
	}, nil)

	var p frameParser
	events := p.feed(stream)
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}
	if p.corrupted != 0 {
		t.Errorf("corrupted = %d, want 0", p.corrupted)
	}

	exec := events[0].GetExecve()
	if events[0].Header.EventType != pb.EventType_EXECVE || exec == nil {
		t.Fatalf("event 0: type=%v body=%T, want EXECVE", events[0].Header.EventType, events[0].Body)
	}
	if exec.Proc.Pid != 4242 || exec.Proc.Ppid != 1 || exec.Proc.Uid != 1000 {
		t.Errorf("exec proc = pid %d ppid %d uid %d, want 4242/1/1000", exec.Proc.Pid, exec.Proc.Ppid, exec.Proc.Uid)
	}
	if exec.Proc.Exe != "/usr/bin/curl" {
		t.Errorf("exec exe = %q, want /usr/bin/curl", exec.Proc.Exe)
	}
	wantArgv := []string{"/usr/bin/curl", "https://example.com"}
	if len(exec.Proc.Argv) != len(wantArgv) {
		t.Fatalf("argv = %v, want %v", exec.Proc.Argv, wantArgv)
	}
	for i := range wantArgv {
		if exec.Proc.Argv[i] != wantArgv[i] {
			t.Errorf("argv[%d] = %q, want %q", i, exec.Proc.Argv[i], wantArgv[i])
		}
	}

	netEv := events[1].GetNet()
	if events[1].Header.EventType != pb.EventType_CONNECT || netEv == nil {
		t.Fatalf("event 1: type=%v, want CONNECT", events[1].Header.EventType)
	}
	if netEv.Op != "connect" || netEv.Family != "ip4" || netEv.Port != 443 {
		t.Errorf("net = op %q family %q port %d", netEv.Op, netEv.Family, netEv.Port)
	}
	if !bytes.Equal(netEv.Ip, []byte{8, 8, 8, 8}) {
		t.Errorf("net ip = %v, want 8.8.8.8", netEv.Ip)
	}

	dns := events[2].GetDns()
	if events[2].Header.EventType != pb.EventType_DNS_QUERY || dns == nil {
		t.Fatalf("event 2: type=%v, want DNS_QUERY", events[2].Header.EventType)
	}
	if dns.ServerIp != "2001:db8::1" || dns.ServerPort != 53 {
		t.Errorf("dns = %s:%d, want 2001:db8::1:53", dns.ServerIp, dns.ServerPort)
	}
	if len(dns.Queries) != 0 {
		t.Errorf("dns queries = %v, want empty (M2 用户态补齐)", dns.Queries)
	}
}

// DNS over IPv4：ServerIp 须是点分十进制。
func TestDnsIp4Server(t *testing.T) {
	e := testDns6Ev()
	e.Family = 4
	copy(e.IP[:4], net.ParseIP("10.0.0.53").To4())
	var p frameParser
	events := p.feed(frameOf(t, e))
	if len(events) != 1 || events[0].GetDns() == nil {
		t.Fatalf("got %v, want 1 dns event", events)
	}
	if got := events[0].GetDns().ServerIp; got != "10.0.0.53" {
		t.Errorf("server ip = %q, want 10.0.0.53", got)
	}
}

// 内核抓的是用户内存原文，非法 UTF-8 须清洗为替换符（proto3 string 要求）。
func TestExecInvalidUtf8Cleaned(t *testing.T) {
	e := testExecEv()
	e.Filename[0] = 0xff // 覆盖 '/'：\xff + "usr/bin/curl"
	var p frameParser
	events := p.feed(frameOf(t, e))
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if got := events[0].GetExecve().Proc.Exe; got != "\uFFFDusr/bin/curl" {
		t.Errorf("exe = %q, want invalid byte replaced and rest kept", got)
	}
}

// 帧跨 read 边界是常态：任意粒度切块喂入须产出同一批事件。
func TestFrameSplitAcrossReads(t *testing.T) {
	stream := bytes.Join([][]byte{
		frameOf(t, testExecEv()),
		frameOf(t, testConnEv()),
		frameOf(t, testDns6Ev()),
	}, nil)
	wantTypes := []pb.EventType{pb.EventType_EXECVE, pb.EventType_CONNECT, pb.EventType_DNS_QUERY}

	for _, step := range []int{1, 2, 3, 5, 7, 13, 64, 99, 511, 1024} {
		var p frameParser
		var got []pb.EventType
		for off := 0; off < len(stream); off += step {
			end := off + step
			if end > len(stream) {
				end = len(stream)
			}
			for _, ev := range p.feed(stream[off:end]) {
				got = append(got, ev.Header.EventType)
			}
		}
		if len(got) != len(wantTypes) {
			t.Fatalf("step %d: got %v, want %v", step, got, wantTypes)
		}
		for i := range wantTypes {
			if got[i] != wantTypes[i] {
				t.Fatalf("step %d: got %v, want %v", step, got, wantTypes)
			}
		}
		if p.corrupted != 0 {
			t.Errorf("step %d: corrupted = %d, want 0", step, p.corrupted)
		}
	}
}

// 坏帧只丢当帧并计数，流不断；帧没收全不算坏。
func TestCorruptFramesSkippedAndStreamSurvives(t *testing.T) {
	u32 := func(v uint32) []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, v)
		return b
	}
	kindFrame := func(kind, total uint32, bodyLen int) []byte {
		body := make([]byte, bodyLen)
		binary.LittleEndian.PutUint32(body[:4], kind)
		return append(u32(total), body...)
	}
	conn := frameOf(t, testConnEv())
	exec := frameOf(t, testExecEv())
	dns := frameOf(t, testDns6Ev())

	for _, tc := range []struct {
		name          string
		chunks        [][]byte
		wantEvents    int
		wantFirstType pb.EventType
		wantCorrupted uint64
	}{
		{"zero length", [][]byte{u32(0), conn}, 1, pb.EventType_CONNECT, 1},
		{"oversize length", [][]byte{u32(2000), conn}, 1, pb.EventType_CONNECT, 1},
		{"total not struct+4", [][]byte{append(u32(100), bytes.Repeat([]byte{'x'}, 96)...), exec}, 1, pb.EventType_EXECVE, 1},
		{"unknown kind", [][]byte{kindFrame(7, 52, 48), dns}, 1, pb.EventType_DNS_QUERY, 1},
		{"total too short to read kind", [][]byte{append(u32(6), 'y', 'y'), conn}, 1, pb.EventType_CONNECT, 1},
		{"truncated frame pending", [][]byte{exec[:100]}, 0, 0, 0},
		{"garbage burst then recovery", [][]byte{bytes.Repeat([]byte{0xff}, 16), conn}, 1, pb.EventType_CONNECT, 4},
	} {
		var p frameParser
		got := 0
		var first pb.EventType
		for _, chunk := range tc.chunks {
			for _, ev := range p.feed(chunk) {
				if got == 0 {
					first = ev.Header.EventType
				}
				got++
			}
		}
		if got != tc.wantEvents {
			t.Errorf("%s: got %d events, want %d", tc.name, got, tc.wantEvents)
		}
		if tc.wantEvents > 0 && first != tc.wantFirstType {
			t.Errorf("%s: first type = %v, want %v", tc.name, first, tc.wantFirstType)
		}
		if p.corrupted != tc.wantCorrupted {
			t.Errorf("%s: corrupted = %d, want %d", tc.name, p.corrupted, tc.wantCorrupted)
		}
	}
}
