// SPDX-License-Identifier: Apache-2.0

package firstseen

import (
	"net"
	"strconv"
	"strings"
	"unicode/utf8"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

// 键四类（驭龙遗产）。kind 参与键编码（first_seen 单表主键须区分
// 类别），同时也是告警 RuleID 后缀。M3 事件侧只抽取前三类；第四类 exe_parent
// 无事件侧来源，仅由 session 在树归档时经 RegisterParentExe 回填。
const (
	KindExe        = "exe"         // (host, exe)
	KindConnTarget = "conn_target" // (host, ip:port)
	KindDNSServer  = "dns_server"  // (host, serverIp:serverPort)
	KindExeParent  = "exe_parent"  // (host, exe, parent_exe)
)

// keySep 用 ASCII 单元分隔符 \x1f：合法主机名（[a-zA-Z0-9.-]）与常规路径几乎
// 不可能包含它。PG TEXT 禁 \x00 所以不可用；残余碰撞面是文件名里人为塞 \x1f
// （后果仅键合并、该变体漏一次首见告警，非安全性塌陷）。
const keySep = "\x1f"

// Obs 是一次首见观察，携带告警元数据（kind/host/agent/ts），免 flush 时反解键。
type Obs struct {
	Key     string
	Kind    string
	Host    string
	AgentID string
	TsMs    int64
	Count   int // 本批窗口内的观测次数（队列内同键合并时累加）
}

func encodeKey(kind, host string, parts ...string) string {
	return kind + keySep + host + keySep + strings.Join(parts, keySep)
}

// sanitize 只清理非法 UTF-8 不截断（键长上限=路径长度量级，PG TEXT 无压力）。
// 事件里的 exe/addr 是攻击者可控输入，非法字节会让整批 upsert 失败，必须在
// 边界处清零。
func sanitize(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "")
}

// ExtractKeys 是事件到观察的纯投影，nil 安全。表驱动：只处理有事件侧抽取的
// 三类事件，其余事件类型一律不产生键。
func ExtractKeys(ev *pb.Event) []Obs {
	if ev == nil || ev.Header == nil {
		return nil
	}
	hdr := ev.Header
	host, agent, ts := sanitize(hdr.Hostname), hdr.AgentId, int64(hdr.TsMs)
	var out []Obs
	switch hdr.EventType {
	case pb.EventType_EXECVE:
		if exe := ev.GetExecve().GetProc().GetExe(); exe != "" {
			out = append(out, Obs{
				Key:     encodeKey(KindExe, host, sanitize(exe)),
				Kind:    KindExe,
				Host:    hdr.Hostname,
				AgentID: agent,
				TsMs:    ts,
				Count:   1,
			})
		}
	case pb.EventType_CONNECT:
		n := ev.GetNet()
		if n == nil {
			return nil
		}
		// 只记连接目标（对端），BIND/ACCEPT 走其他 EventType 不进此分支。
		// 跳过：空地址、:0、环回。IsLoopback 是 127.0.0.0/8 的超集，同时挡
		// ::1 与 v4-mapped 环回——brief 只要求 127/8，这里取更严的一侧。
		if n.GetPort() == 0 || len(n.GetIp()) == 0 {
			return nil
		}
		ip := net.IP(n.GetIp())
		if ip.IsLoopback() {
			return nil
		}
		out = append(out, Obs{
			Key:     encodeKey(KindConnTarget, host, net.JoinHostPort(sanitize(ip.String()), strconv.FormatUint(uint64(n.GetPort()), 10))),
			Kind:    KindConnTarget,
			Host:    hdr.Hostname,
			AgentID: agent,
			TsMs:    ts,
			Count:   1,
		})
	case pb.EventType_DNS_QUERY:
		d := ev.GetDns()
		if d == nil || d.GetServerIp() == "" || d.GetServerPort() == 0 {
			return nil
		}
		out = append(out, Obs{
			Key:     encodeKey(KindDNSServer, host, net.JoinHostPort(sanitize(d.GetServerIp()), strconv.FormatUint(uint64(d.GetServerPort()), 10))),
			Kind:    KindDNSServer,
			Host:    hdr.Hostname,
			AgentID: agent,
			TsMs:    ts,
			Count:   1,
		})
	}
	return out
}
