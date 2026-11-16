// xiezhi eBPF 采集器（M1-A）：fork/exec/exit/connect 四事件，ringbuf 上抛。
// 目标内核 5.8+（ringbuf）；4.19 目标的 perf buffer 降级路径在 M5。
// 结构体布局与 agent/internal/collector/ebpf/ebpf.go 的 Go 镜像严格一致（显式 pad）。
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET 2
#define AF_INET6 10

#define EV_KIND_FORK 1
#define EV_KIND_EXEC 2
#define EV_KIND_EXIT 3
#define EV_KIND_CONNECT 4

/* 显式对齐：u64 前补一个 u32，Go 侧镜像同布局，binary.Read 直接读 */
struct ev_hdr {
	__u32 kind;
	__u32 pid;
	__u32 ppid;
	__u32 pad;
	__u64 ts_ns;
};

struct ev_fork {
	struct ev_hdr h;
	__u32 child_pid;
	__u32 pad2;
	__u64 child_start;
};

struct ev_exec {
	struct ev_hdr h;
	char comm[16];
	char filename[128];
	char argv[256];
	__u32 argv_len;
	__u32 uid;
	__u64 start_ticks; /* task->start_time；session 层 pid 复用硬闸（M4） */
};

struct ev_exit {
	struct ev_hdr h;
	__u32 code;
	__u32 pad2;
};

struct ev_connect {
	struct ev_hdr h;
	__u8 family;
	__u8 pad1;
	__u16 port;
	__u8 ip[16];
};

struct ev_dns {
	struct ev_hdr h;
	__u8 family;
	__u8 pad1;
	__u16 port;
	__u8 ip[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

/* tgid -> 父信息。线程不进来（fork 处过滤非 leader）。 */
struct proc_rec {
	__u32 ppid;
	__u64 start_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct proc_rec);
} procs SEC(".maps");

static __always_inline struct proc_rec *lookup_proc(__u32 tgid)
{
	return bpf_map_lookup_elem(&procs, &tgid);
}

/* raw tracepoint：BPF_PROG 宏按 bpf_raw_tracepoint_args 布局取参（tp 类型的
 * ctx 带 perf 头，直接解引用会被 verifier 拒），且绕过 perf 层更快。 */
SEC("raw_tp/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	__u32 ctgid = BPF_CORE_READ(child, tgid);
	if (ctgid != BPF_CORE_READ(child, pid))
		return 0; /* 线程 */

	struct proc_rec rec = {
		.ppid = BPF_CORE_READ(parent, tgid),
		.start_ns = BPF_CORE_READ(child, start_time),
	};
	bpf_map_update_elem(&procs, &ctgid, &rec, BPF_ANY);

	struct ev_fork *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	struct proc_rec *pr = lookup_proc(BPF_CORE_READ(parent, tgid));
	e->h.kind = EV_KIND_FORK;
	e->h.pid = BPF_CORE_READ(parent, tgid);
	e->h.ppid = pr ? pr->ppid : 0;
	e->h.pad = 0;
	e->h.ts_ns = bpf_ktime_get_ns();
	e->child_pid = ctgid;
	e->pad2 = 0;
	e->child_start = rec.start_ns;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("raw_tp/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *task, pid_t old_pid, struct linux_binprm *bprm)
{
	struct ev_exec *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	struct proc_rec *pr = lookup_proc(tgid);

	e->h.kind = EV_KIND_EXEC;
	e->h.pid = tgid;
	e->h.ppid = pr ? pr->ppid : BPF_CORE_READ(task, real_parent, tgid);
	e->h.pad = 0;
	e->h.ts_ns = bpf_ktime_get_ns();
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	/* bprm->filename 是 const char*，先取指针再读串（直接 STR_INTO 会把
	 * 指针字节当内容读出乱码） */
	const char *fn = BPF_CORE_READ(bprm, filename);
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), fn);

	/* argv 原文（用户内存）。短命进程在用户态补读会 miss，内核侧抓最稳；
	 * 256B 截断 M1 够用（SecEBL 语料 p99=113 token）。 */
	e->argv_len = 0;
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (mm) {
		__u64 arg_start = BPF_CORE_READ(mm, arg_start);
		__u64 arg_end = BPF_CORE_READ(mm, arg_end);
		__u64 len = arg_end - arg_start;
		if (len > sizeof(e->argv))
			len = sizeof(e->argv);
		if (arg_start && len &&
		    bpf_probe_read_user(&e->argv, len, (void *)arg_start) == 0)
			e->argv_len = (__u32)len;
	}
	e->uid = bpf_get_current_uid_gid();
	e->start_ticks = BPF_CORE_READ(task, start_time);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("raw_tp/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *task)
{
	__u32 tgid = BPF_CORE_READ(task, tgid);
	if (tgid != BPF_CORE_READ(task, pid))
		return 0; /* 线程 exit：进程随后还会发 */


	struct ev_exit *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	/* K-3（R8.4 审计）：先查后删——原顺序 delete 在前，pr 恒 NULL，
	 * exit 帧的 ppid 恒 0（死值；当前 agent 侧未消费该字段故未显形）。 */
	struct proc_rec *pr = lookup_proc(tgid);
	bpf_map_delete_elem(&procs, &tgid);
	e->h.kind = EV_KIND_EXIT;
	e->h.pid = tgid;
	e->h.ppid = pr ? pr->ppid : 0;
	e->h.pad = 0;
	e->h.ts_ns = bpf_ktime_get_ns();
	e->code = BPF_CORE_READ(task, exit_code);
	e->pad2 = 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/security_socket_connect")
int BPF_KPROBE(on_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	__u16 family = BPF_CORE_READ(address, sa_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	struct ev_connect *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	struct proc_rec *pr = lookup_proc(tgid);

	e->h.kind = EV_KIND_CONNECT;
	e->h.pid = tgid;
	e->h.ppid = pr ? pr->ppid : 0;
	e->h.pad = 0;
	e->h.ts_ns = bpf_ktime_get_ns();
	e->family = family == AF_INET ? 4 : 6;
	e->pad1 = 0;
	__builtin_memset(e->ip, 0, sizeof(e->ip));
	if (family == AF_INET) {
		struct sockaddr_in *sa4 = (struct sockaddr_in *)address;
		e->port = __bpf_ntohs(BPF_CORE_READ(sa4, sin_port));
		bpf_core_read(e->ip, 4, &sa4->sin_addr);
	} else {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)address;
		e->port = __bpf_ntohs(BPF_CORE_READ(sa6, sin6_port));
		bpf_core_read(e->ip, 16, &sa6->sin6_addr);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* DNS 查询目标（53/5353）。域名解析留 M2 用户态补，内核只记目标。
 * 6.8 的 udp_sendmsg 是三参签名（3.10 线在 driver/src/xiezhi_hooks.c 用四参）。 */
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(on_dns, struct sock *sk, struct msghdr *msg, size_t len)
{
	struct sockaddr *name = NULL;
	__u16 family = 0, port = 0;
	__u8 iplen = 0;
	const void *ip = NULL;
	struct sockaddr_in sa4;
	struct sockaddr_in6 sa6;
	struct ev_dns *e;
	__u32 tgid;
	struct proc_rec *pr;

	name = BPF_CORE_READ(msg, msg_name);
	if (name) {
		family = BPF_CORE_READ(name, sa_family);
		if (family == AF_INET) {
			struct sockaddr_in *sa = (struct sockaddr_in *)name;
			port = __bpf_ntohs(BPF_CORE_READ(sa, sin_port));
			ip = &sa->sin_addr;
			iplen = 4;
		} else if (family == AF_INET6) {
			struct sockaddr_in6 *sa6p = (struct sockaddr_in6 *)name;
			port = __bpf_ntohs(BPF_CORE_READ(sa6p, sin6_port));
			ip = &sa6p->sin6_addr;
			iplen = 16;
		}
	} else {
		/* connect 过的 UDP socket：sock 公共字段兜底 */
		family = BPF_CORE_READ(sk, __sk_common.skc_family);
		port = __bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
		if (family == AF_INET) {
			ip = &sk->__sk_common.skc_daddr;
			iplen = 4;
		} else if (family == AF_INET6) {
			ip = &sk->__sk_common.skc_v6_daddr;
			iplen = 16;
		}
	}
	(void)sa4; (void)sa6;
	if (!ip || (port != 53 && port != 5353))
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	tgid = bpf_get_current_pid_tgid() >> 32;
	pr = lookup_proc(tgid);
	e->h.kind = 5; /* XIEZHI_KIND_DNS，与 driver/include/xiezhi_frame.h 对齐 */
	e->h.pid = tgid;
	e->h.ppid = pr ? pr->ppid : 0;
	e->h.pad = 0;
	e->h.ts_ns = bpf_ktime_get_ns();
	e->family = family == AF_INET ? 4 : 6;
	e->pad1 = 0;
	e->port = port;
	__builtin_memset(e->ip, 0, sizeof(e->ip));
	bpf_probe_read_kernel(e->ip, iplen, ip);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
