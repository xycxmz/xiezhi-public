// SPDX-License-Identifier: Apache-2.0

//go:build linux

package journal

import (
	"regexp"
	"strings"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

// rawLimit 是 Raw 字段的字节截断上界（untrusted 数据，截断后再洗 UTF-8，
// 截断可能劈开多字节字符，由 ToValidUTF8 收尾）。
const rawLimit = 256

// 两段式解析：行 = 可选 syslog 头（时间戳+主机）+ 程序标签 + 消息体。
// 先按位置拆出标签再分派，命令内容里伪造 "Accepted password for ..." 的
// 文本不会被当成 sshd 事件（标签来自位置，不来自内容匹配）。
var (
	// syslog 头两种形态：传统 "Nov  1 10:00:00 host " 与 ISO8601（journald
	// short-iso）"2026-11-12T10:00:00.123456+08:00 host "。
	syslogHeadRe = regexp.MustCompile(
		`^(?:(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2})?))\s+\S+\s+`)

	// 程序标签：sshd[123]: / sudo: / su: / CROND[456]:
	tagRe = regexp.MustCompile(`^([A-Za-z0-9_-]+?)(?:\[\d+\])?:\s?(.*)$`)
)

// kind 常量与 proto event.proto v0.4 JournalAuthEvent.Kind 对齐。
const (
	kindSSHLogin = "ssh_login"
	kindSudo     = "sudo"
	kindSU       = "su"
	kindCron     = "cron"
)

// sshd 认证结果行。"invalid user " 前缀（暴力破解最常见形态）剥掉后取
// 尝试的用户名。
var (
	sshAcceptedRe = regexp.MustCompile(`^Accepted \S+ for (?:invalid user )?(\S+) from (\S+) port \d+`)
	sshFailedRe   = regexp.MustCompile(`^Failed \S+ for (?:invalid user )?(\S+) from (\S+) port \d+`)
)

func parseSSH(msg string) *pb.JournalAuthEvent {
	if m := sshAcceptedRe.FindStringSubmatch(msg); m != nil {
		return &pb.JournalAuthEvent{Kind: kindSSHLogin, User: m[1], SourceIp: m[2], Result: "success"}
	}
	if m := sshFailedRe.FindStringSubmatch(msg); m != nil {
		return &pb.JournalAuthEvent{Kind: kindSSHLogin, User: m[1], SourceIp: m[2], Result: "failed"}
	}
	return nil
}

// sudo：user=执行 sudo 的人（sudoer）。proto v0.4 JournalAuthEvent 无 detail
// 字段，command 落在 Raw（原始行截断）里；失败形态（NOT in sudoers /
// incorrect password / command not allowed）单独判 result=failed。
var (
	sudoUserRe = regexp.MustCompile(`^(\S+) : (.+)$`)
	sudoFailRe = regexp.MustCompile(`NOT in sudoers|incorrect password attempt|command not allowed`)
)

func parseSudo(msg string) *pb.JournalAuthEvent {
	m := sudoUserRe.FindStringSubmatch(msg)
	if m == nil {
		return nil
	}
	result := "success"
	if sudoFailRe.MatchString(m[2]) {
		result = "failed"
	}
	return &pb.JournalAuthEvent{Kind: kindSudo, User: m[1], Result: result}
}

// su：FAILED SU (user) to root 是失败形态，(to root) alice on 是成功形态
// （util-linux 两种都进 auth.log）。
var (
	suFailedRe  = regexp.MustCompile(`^FAILED SU \((\S+)\) to (\S+)`)
	suSuccessRe = regexp.MustCompile(`^\(to (\S+)\) (\S+) on `)
)

func parseSU(msg string) *pb.JournalAuthEvent {
	if m := suFailedRe.FindStringSubmatch(msg); m != nil {
		return &pb.JournalAuthEvent{Kind: kindSU, User: m[1], Result: "failed"}
	}
	if m := suSuccessRe.FindStringSubmatch(msg); m != nil {
		return &pb.JournalAuthEvent{Kind: kindSU, User: m[2], Result: "success"}
	}
	return nil
}

// cron：CRON（Debian 系）/ CROND（RHEL 系）同形消息 "(user) CMD (...)"。
// CMDOUT 行不带 "CMD ("，不匹配。
var cronCmdRe = regexp.MustCompile(`^\((\S+)\) CMD `)

func parseCron(msg string) *pb.JournalAuthEvent {
	if m := cronCmdRe.FindStringSubmatch(msg); m != nil {
		return &pb.JournalAuthEvent{Kind: kindCron, User: m[1], Result: "success"}
	}
	return nil
}

// parsers 是标签 -> 消息解析器的分派表。CRON/CROND 在 normalize 时都折到
// "cron"。表外标签（systemd、sshd 非认证行等）返回 nil 由调用方计数跳过。
var parsers = map[string]func(string) *pb.JournalAuthEvent{
	"sshd": parseSSH,
	"sudo": parseSudo,
	"su":   parseSU,
	"cron": parseCron,
}

// ParseLine 是纯函数入口：一行日志进，一个事件出；解析不了返回 nil。
// Raw 携带清洗+截断后的原始整行（untrusted，不得直接进规则引擎）。
func ParseLine(orig string) *pb.JournalAuthEvent {
	body := orig
	if head := syslogHeadRe.FindString(body); head != "" {
		body = body[len(head):]
	}
	m := tagRe.FindStringSubmatch(body)
	if m == nil {
		return nil
	}
	program := strings.ToLower(m[1])
	if program == "crond" {
		program = "cron"
	}
	parse, known := parsers[program]
	if !known {
		return nil
	}
	ev := parse(m[2])
	if ev == nil {
		return nil
	}
	ev.User = sanitizeRaw(ev.User)
	ev.SourceIp = sanitizeRaw(ev.SourceIp)
	ev.Raw = sanitizeRaw(orig)
	return ev
}

// sanitizeRaw 字节截断后洗 UTF-8：proto3 string 要求合法 UTF-8，否则
// gRPC marshal 拒批（与 lkm/ebpf 的 cstr 同一教训）。
func sanitizeRaw(line string) string {
	if len(line) > rawLimit {
		line = line[:rawLimit]
	}
	return strings.ToValidUTF8(line, "\uFFFD")
}
