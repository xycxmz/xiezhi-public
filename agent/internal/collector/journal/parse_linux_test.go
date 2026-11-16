// SPDX-License-Identifier: Apache-2.0

//go:build linux

package journal

import (
	"strings"
	"testing"
	"unicode/utf8"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

// 真样本表驱动：期望值来自 auth.log 行格式（rsyslog 传统头 / 无头 / ISO 头），
// 不是从实现回填。
func TestParseLine(t *testing.T) {
	longCmd := "sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/echo " + strings.Repeat("A", 400)
	cases := []struct {
		name string
		line string
		want *pb.JournalAuthEvent // nil = 解析不了
	}{
		{
			name: "sshd accepted publickey with syslog head",
			line: "Nov 12 10:00:01 web01 sshd[12345]: Accepted publickey for alice from 10.0.0.5 port 51000 ssh2: RSA SHA256:abc",
			want: &pb.JournalAuthEvent{Kind: "ssh_login", User: "alice", SourceIp: "10.0.0.5", Result: "success"},
		},
		{
			name: "sshd accepted password bare",
			line: "sshd[99]: Accepted password for bob from 192.168.1.7 port 51001 ssh2",
			want: &pb.JournalAuthEvent{Kind: "ssh_login", User: "bob", SourceIp: "192.168.1.7", Result: "success"},
		},
		{
			name: "sshd accepted with iso head",
			line: "2026-11-12T10:00:00.123456+08:00 web01 sshd[1]: Accepted password for dave from 10.1.2.3 port 2222 ssh2",
			want: &pb.JournalAuthEvent{Kind: "ssh_login", User: "dave", SourceIp: "10.1.2.3", Result: "success"},
		},
		{
			name: "sshd failed password",
			line: "Nov 12 10:00:05 web01 sshd[12346]: Failed password for root from 203.0.113.9 port 22 ssh2",
			want: &pb.JournalAuthEvent{Kind: "ssh_login", User: "root", SourceIp: "203.0.113.9", Result: "failed"},
		},
		{
			name: "sshd failed password invalid user",
			line: "sshd[12347]: Failed password for invalid user admin from 198.51.100.7 port 41234 ssh2",
			want: &pb.JournalAuthEvent{Kind: "ssh_login", User: "admin", SourceIp: "198.51.100.7", Result: "failed"},
		},
		{
			name: "sshd failed keyboard-interactive",
			line: "sshd[8]: Failed keyboard-interactive/pam for root from 192.0.2.10 port 50000 ssh2",
			want: &pb.JournalAuthEvent{Kind: "ssh_login", User: "root", SourceIp: "192.0.2.10", Result: "failed"},
		},
		{
			name: "sudo success",
			line: "sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
			want: &pb.JournalAuthEvent{Kind: "sudo", User: "alice", Result: "success"},
		},
		{
			name: "sudo success with head",
			line: "Nov 12 10:05:00 web01 sudo: bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/apt update",
			want: &pb.JournalAuthEvent{Kind: "sudo", User: "bob", Result: "success"},
		},
		{
			name: "sudo not in sudoers",
			line: "sudo: mallory : user NOT in sudoers ; TTY=unknown ; PWD=/home/mallory ; USER=root ; COMMAND=/bin/bash",
			want: &pb.JournalAuthEvent{Kind: "sudo", User: "mallory", Result: "failed"},
		},
		{
			name: "sudo incorrect password attempts",
			line: "sudo: eve : 1 incorrect password attempts ; TTY=pts/2 ; PWD=/home/eve ; USER=root ; COMMAND=/bin/sh",
			want: &pb.JournalAuthEvent{Kind: "sudo", User: "eve", Result: "failed"},
		},
		{
			name: "su failed",
			line: "su[2319]: FAILED SU (eve) to root on /dev/pts/3",
			want: &pb.JournalAuthEvent{Kind: "su", User: "eve", Result: "failed"},
		},
		{
			name: "su success",
			line: "su: (to root) alice on /dev/pts/0",
			want: &pb.JournalAuthEvent{Kind: "su", User: "alice", Result: "success"},
		},
		{
			name: "cron rhel form",
			line: "CROND[28147]: (root) CMD (/usr/bin/backup.sh)",
			want: &pb.JournalAuthEvent{Kind: "cron", User: "root", Result: "success"},
		},
		{
			name: "cron debian form with head",
			line: "Nov 12 03:17:01 web01 CRON[999]: (www-data) CMD (php /var/www/cron.php)",
			want: &pb.JournalAuthEvent{Kind: "cron", User: "www-data", Result: "success"},
		},
		{
			name: "cron cmdout is not a command",
			line: "CRON[999]: (root) CMDOUT (backup: 102 files)",
			want: nil,
		},
		{
			name: "unrelated program",
			line: "Nov 12 10:00:00 web01 systemd[1]: Started Session 5 of user alice.",
			want: nil,
		},
		{
			name: "sshd connection noise",
			line: "sshd[12348]: Connection closed by 10.0.0.5 port 51000 [preauth]",
			want: nil,
		},
		{
			name: "garbage line",
			line: "RANDOM GARBAGE WITHOUT TAG",
			want: nil,
		},
		{
			name: "empty line",
			line: "",
			want: nil,
		},
		{
			// 分派按位置：命令内容里伪造 sshd 行不得变成 ssh_login
			name: "forged sshd text inside sudo command stays sudo",
			line: "sudo: alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/echo 'sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2'",
			want: &pb.JournalAuthEvent{Kind: "sudo", User: "alice", Result: "success"},
		},
		{
			name: "long line",
			line: longCmd,
			want: &pb.JournalAuthEvent{Kind: "sudo", User: "alice", Result: "success"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseLine(tc.line)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("ParseLine = %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("ParseLine = nil, want %+v", tc.want)
			}
			if got.Kind != tc.want.Kind || got.User != tc.want.User ||
				got.SourceIp != tc.want.SourceIp || got.Result != tc.want.Result {
				t.Errorf("got kind=%q user=%q ip=%q result=%q, want %+v",
					got.Kind, got.User, got.SourceIp, got.Result, tc.want)
			}
			if !utf8.ValidString(got.Raw) {
				t.Errorf("Raw not valid UTF-8: %q", got.Raw)
			}
		})
	}
}

// Raw 截断 256B（字节口径）且仍合法 UTF-8。
func TestParseLineRawTruncation(t *testing.T) {
	line := "sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/echo " + strings.Repeat("B", 600)
	ev := ParseLine(line)
	if ev == nil {
		t.Fatal("ParseLine = nil, want sudo event")
	}
	if len(ev.Raw) != 256 {
		t.Errorf("len(Raw) = %d, want 256", len(ev.Raw))
	}
	if !utf8.ValidString(ev.Raw) {
		t.Error("Raw not valid UTF-8 after truncation")
	}
	if !strings.HasPrefix(ev.Raw, "sudo: alice : TTY=") {
		t.Errorf("Raw = %q..., want prefix of original line", ev.Raw[:30])
	}
}

// 非法 UTF-8 字节的用户名：User/Raw 都必须被洗成合法 UTF-8（proto3 string
// 要求，gRPC marshal 会拒批）。
func TestParseLineSanitizesInvalidUTF8(t *testing.T) {
	line := "sshd[1]: Accepted password for \xff\xfebob from \x8010.0.0.9 port 22 ssh2"
	ev := ParseLine(line)
	if ev == nil {
		t.Fatal("ParseLine = nil, want ssh event")
	}
	if !utf8.ValidString(ev.User) || !utf8.ValidString(ev.SourceIp) || !utf8.ValidString(ev.Raw) {
		t.Errorf("fields not valid UTF-8: user=%q ip=%q", ev.User, ev.SourceIp)
	}
}
