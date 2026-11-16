// SPDX-License-Identifier: Apache-2.0

package intent

import (
	"context"
	"regexp"
)

// Builtin 是占位标注器（大声声明）：关键词→标签的确定性正则映射表，
// 非语义模型。语义覆盖 = M3 seed 规则集（2026-10~11 战役实证行为）的
// 标签化外推，SecEBL sidecar 部署后由 HTTPLabeler 整体替换。
// 表驱动纯函数：同一输入永远同一输出，无共享可变状态。
type Builtin struct{}

func NewBuiltin() *Builtin { return &Builtin{} }

// Label 顺序遍历表，命中任一模式即给该标签（score=1.0），每标签至多一次。
// 输出顺序 = 表顺序，确定性的。
func (b *Builtin) Label(_ context.Context, cmdline string) []Label {
	var out []Label
	for _, tp := range builtinTable {
		for _, re := range tp.res {
			if re.MatchString(cmdline) {
				out = append(out, Label{Tag: tp.tag, Score: 1.0})
				break
			}
		}
	}
	return out
}

type tagRules struct {
	tag string
	res []*regexp.Regexp
}

func mustRe(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i] = regexp.MustCompile(`(?i)` + p)
	}
	return out
}

// builtinTable 约 32 个标签。短词一律 \b 包裹（如 tor 不得命中 monitor）。
// 攻击面标签对应 SecEBL L2 分值参考量级，分值由策略文件定，本表只管语义。
var builtinTable = []tagRules{
	{tag: "recon_port_scan", res: mustRe(
		`\bnmap\b`, `\bmasscan\b`, `\bzgrab\b`, `\brustscan\b`, `\bnaabu\b`)},
	{tag: "download_and_execute", res: mustRe(
		`(curl|wget)[^|;]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b`)},
	// -O /dev/null 是丢弃型下载（健康检查形态：容器服务每分钟 wget localhost
	// -O /dev/null 凑满桶阈值，产线实证误分）。-o/-O 模式改白名单语义：
	// 输出落敏感目录（tmp/dev/shm/var/tmp/root/home/etc）或相对路径才计分。
	{tag: "remote_download", res: mustRe(
		`\b(curl|wget)\b[^|;]*(/tmp/|/dev/shm/|/var/tmp/)`,
		`\b(curl|wget)\b[^|;]*\s-[oO]\s?(/(tmp|dev/shm|var/tmp|root|home|etc)|[^/\s])`)},
	// cred_material_read 的路径模式必须带读取/外传/修改动词前缀：纯引用
	// （ssh -i /root/.ssh/id_bench）不是读取，五轮实测两次引用即凑满 8.0
	// 阈值，benign 运维 ssh 全中（FP01/02 根因）。
	{tag: "cred_material_read", res: mustRe(
		`(cat|cp|mv|rm|base64|xxd|strings|grep|head|tail|less|more|find|tar|scp|rsync|chmod|chown)\b[^|;]*/root/\.(ssh|aws|kube)\b`,
		`(cat|cp|mv|rm|base64|xxd|strings|grep|head|tail|less|more|find|tar|scp|rsync|chmod|chown)\b[^|;]*/home/\w+/\.(ssh|aws|kube)\b`,
		`(cat|cp|mv|rm|base64|xxd|strings|grep|head|tail|less|more|find|tar|scp|rsync|chmod|chown)\b[^|;]*\bid_rsa\b`,
		`(cat|cp|mv|rm|base64|xxd|strings|grep|head|tail|less|more|find|tar|scp|rsync|chmod|chown)\b[^|;]*authorized_keys`,
		`(cat|cp|mv|base64|xxd|strings|grep|tar|scp|rsync)\b[^|;]*\.git-credentials`,
		`(cat|cp|mv|base64|xxd|strings|grep|tar|scp|rsync)\b[^|;]*\.npmrc\b`,
		`(cat|cp|mv|base64|xxd|strings|grep|tar|scp|rsync)\b[^|;]*\.docker/config`,
		`(cat|grep|head|tail|less|more|find)\b[^|;]*\.(env|pem|key|pfx)\b`)},
	{tag: "persistence_cron", res: mustRe(
		`\bcrontab\b`, `/etc/cron\.(d|daily|hourly|weekly|monthly)\b`, `/etc/crontab\b`, `/var/spool/cron\b`)},
	{tag: "mining_indicator", res: mustRe(
		`\bxmrig\b`, `\bminerd\b`, `\bkdevtmpfsi\b`, `\bkinsing\b`,
		`stratum\+tcp`, `pool\.minexmr`, `nanopool`, `supportxmr`,
		`--donate-level`, `--cpu-max-threads`, `--url=stratum`)},
	{tag: "tunnel_setup", res: mustRe(
		`trycloudflare\.com`, `cloudflared\s+(tunnel|access|--url)`, `\bngrok\b`,
		`\bfrpc\b`, `\bfrps\b`, `\bchisel\b`, `\bssh\b[^|;]*\s-[A-Za-z]*R\b`)},
	{tag: "privesc_sudo", res: mustRe(
		`\bsudo\b`, `\bsu\s+-`, `\bsu\s+root\b`, `\bpkexec\b`)},
	{tag: "user_creation", res: mustRe(
		`\buseradd\b`, `\badduser\b`, `\bchpasswd\b`, `passwd\s+--stdin`)},
	{tag: "user_mod_root", res: mustRe(
		`usermod\b[^|;]*\b(sudo|wheel|docker|root)\b`, `gpasswd\s+-a\b`)},
	{tag: "reverse_shell", res: mustRe(
		`/dev/tcp/`, `\b(nc|ncat)\b[^|;]*\s-e\b`, `socat\b[^|;]*exec:`, `mkfifo\b[^|;]*(backpipe|/tmp/)`)},
	{tag: "bind_shell", res: mustRe(
		`\b(nc|ncat|socat)\b[^|;]*(-l\b|--listen|TCP-LISTEN)`)},
	{tag: "shell_history_clear", res: mustRe(
		`history\s+-c\b`, `unset\s+HISTFILE`, `HISTFILE\s*=\s*/dev/null`,
		`(rm|shred|truncate)\b[^|;]*(bash_history|zsh_history)`)},
	{tag: "audit_log_tamper", res: mustRe(
		`(systemctl|service)\s+(stop|disable|mask)\s+(auditd|rsyslog|syslog-ng)\b`,
		`\brm\b[^|;]*(/var/log/audit|/var/log/auth\.log|/var/log/secure)`,
		`setenforce\s+0`, `>\s*/var/log/(wtmp|lastlog)`)},
	{tag: "ssh_authorized_key_write", res: mustRe(
		`(>>?|tee\s+-a)\s*[^|;#\s]*authorized_keys`)},
	{tag: "setuid_change", res: mustRe(
		`chmod\s+4[0-7]{3}\b`, `chmod\b[^|;]*u\+s\b`)},
	{tag: "lkm_load", res: mustRe(
		`\binsmod\b`, `\brmmod\b`, `\bmodprobe\b`)},
	{tag: "bpf_load", res: mustRe(
		`\bbpftool\b`, `\bbpftrace\b`)},
	{tag: "docker_abuse", res: mustRe(
		`\bdocker\b[^|;]*(--privileged\b|-v\s+/:)`)},
	{tag: "kube_credential_read", res: mustRe(
		`\.kube/config`, `/etc/kubernetes/(admin|kubelet)\.conf`)},
	{tag: "cloud_credential_read", res: mustRe(
		`169\.254\.169\.254`, `100\.100\.100\.200`, `get-caller-identity`)},
	{tag: "proc_environ_dump", res: mustRe(
		`/proc/[0-9]+/environ`, `\bstrings\b\s+/proc/`)},
	{tag: "data_archive", res: mustRe(
		`\btar\b[^|;]*(\sczf|\s-zcvf)`, `\bzip\b\s+-r\b`, `\b7z\b\s+a\b`, `\brar\b\s+a\b`)},
	{tag: "data_upload", res: mustRe(
		`\bscp\b[^|;]*@`, `\brsync\b[^|;]*@`, `\bcurl\b[^|;]*(-T\s|--upload-file\s)`)},
	{tag: "obfuscated_payload", res: mustRe(
		`\bbase64\b[^|;]*\s(-d|-D|--decode)\b[^|;]*\|`, `\|\s*base64\b[^|;]*\s(-d|-D|--decode)\b`,
		`eval\s+\$\(echo`, `\bxxd\b\s+-r`, `[A-Za-z0-9+/]{120,}={0,2}`)},
	{tag: "staging_exec", res: mustRe(
		`chmod\s+(\+x|[0-7]{3,4})\s+(/tmp/|/dev/shm/|/var/tmp/)`, `(/tmp|/dev/shm|/var/tmp)/\S+\s*&&`)},
	{tag: "proxy_anonymizer", res: mustRe(
		`\bproxychains[0-9]?\b`, `\btorsocks\b`, `\btor\b\s`)},
	{tag: "disk_wipe", res: mustRe(
		`dd\s+[^|;]*of=/dev/(sd|vd|nvme|xvd|mmcblk)`, `\bmkfs(\.\w+)?\b`, `\bwipefs\b`, `shred\b[^|;]*\s/dev/`)},
	{tag: "interpreter_one_liner", res: mustRe(
		`\bpython[23]?\b\s+-c\b`, `\bperl\b\s+-e\b`, `\bruby\b\s+-e\b`, `\bnode\b\s+-e\b`)},
	{tag: "package_install", res: mustRe(
		`apt(-get)?\s+install\b`, `yum\s+install\b`, `dnf\s+install\b`,
		`apk\s+add\b`, `pip3?\s+install\b`, `npm\s+(install|\bi\b)`)},
	{tag: "service_restart", res: mustRe(
		`systemctl\s+(restart|start|stop|reload)\b`, `\bservice\b[^|;]*\s(restart|start|stop)\b`,
		`supervisorctl\s+restart\b`, `/etc/init\.d/\S+\s+(restart|start|stop)\b`)},
	{tag: "config_edit", res: mustRe(
		`\bsed\b\s+[^|;]*(-i\b|--in-place\b)`, `\btee\b\s+/etc/`)},
}
