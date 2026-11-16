#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/sock.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/nsproxy.h>
#include <linux/mnt_namespace.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>
#include <linux/mman.h>
#include <linux/ptrace.h>
#include <linux/prctl.h>

#include "xiezhi_frame.h"
#include "xiezhi_hooks.h"
#include "xiezhi_ring.h"
#include "xiezhi_trace.h"

#define XIEZHI_RING_BYTES (1024 * 1024)

static struct xiezhi_ring ring;

/*
 * init(=host) mount namespace; NULL means unknown (kallsyms miss on >=5.7
 * builds) and the container filter degrades to emit, matching pre-filter
 * behavior. Resolved once in xiezhi_collect_init.
 */
static struct mnt_namespace *init_mnt_ns;

/* file_open paths are host-scoped: a container mount-ns open renders
 * namespace-relative ("/etc/passwd" at the overlay root) and misfires host
 * path rules. Container tagging is follow-up work (dentry mount). */
static int in_host_mnt_ns(void)
{
	if (!init_mnt_ns || !current->nsproxy)
		return 1;
	return current->nsproxy->mnt_ns == init_mnt_ns;
}

/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */
#define ARG1(regs) ((regs)->di)
#define ARG2(regs) ((regs)->si)
#define ARG3(regs) ((regs)->dx)
#define ARG4(regs) ((regs)->cx)

#define AF_INET_2 2
#define AF_INET6_10 10

static void fill_hdr(struct ev_hdr *h, __u32 kind)
{
	struct task_struct *parent;

	h->kind = kind;
	h->pid = task_tgid_vnr(current);
	/* K-1（R8.4 审计）：real_parent 及其 pid 链在 release_task 路径是同步
	 * 释放（3.10 put_pid 直接 kmem_cache_free），裸读有 UAF 面。task_struct
	 * 本体 RCU 释放——持 rcu_read_lock 读 ->tgid；pid 链部分 task_tgid_vnr
	 * 仍可能触已释放 pid（窄窗），失败语义取 0（会话树父链缺一次，无害）。 */
	rcu_read_lock();
	parent = rcu_dereference(current->real_parent);
	if (parent)
		h->ppid = task_tgid_vnr(parent);
	else
		h->ppid = 0;
	rcu_read_unlock();
	h->pad = 0;
	h->ts_ns = ktime_to_ns(ktime_get());
}

static int emit(const void *ev, __u32 len)
{
	xiezhi_ring_put(&ring, ev, len);
	return 0;
}

/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */
static int emit_generic(__u32 kind, __u64 detail)
{
	struct ev_generic e;

	memset(&e, 0, sizeof(e));
	fill_hdr(&e.h, kind);
	e.detail = detail;
	return emit(&e, sizeof(e));
}

/* ---- execve / execveat ---- */

static int emit_exec(const char __user *u_fn,
		     const char __user *const __user *u_argv)
{
	struct ev_exec e;
	const char __user *arg;
	int i;
	u32 off = 0;

	if (!current->mm)
		return 0; /* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */

	memset(&e, 0, sizeof(e));
	fill_hdr(&e.h, XIEZHI_KIND_EXEC);
	get_task_comm(e.comm, current);
	e.uid = __kuid_val(current_uid());
	/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
	e.start_ticks = (__u64)current->start_time.tv_sec * NSEC_PER_SEC +
			current->start_time.tv_nsec;
#else
	e.start_ticks = current->start_time;
#endif

	pagefault_disable();
	if (strncpy_from_user(e.filename, u_fn, sizeof(e.filename) - 1) < 0)
		e.filename[0] = '\0';

	/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */
	for (i = 0; i < 8 && off + 1 < sizeof(e.argv); i++) {
		if (__get_user(arg, &u_argv[i]) || !arg)
			break;
		if (i > 0 && off < sizeof(e.argv))
			e.argv[off++] = '\0';
		{
			long n = strncpy_from_user((char *)e.argv + off, arg,
						   sizeof(e.argv) - off - 1);
			if (n <= 0)
				break;
			off += n;
		}
	}
	pagefault_enable();
	e.argv_len = off;

	return emit(&e, sizeof(e));
}

static int on_execve(struct kprobe *p, struct pt_regs *regs)
{
	return emit_exec((const char __user *)ARG1(regs),
			 (const char __user *const __user *)ARG2(regs));
}

/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */
static int on_execveat(struct kprobe *p, struct pt_regs *regs)
{
	return emit_exec((const char __user *)ARG2(regs),
			 (const char __user *const __user *)ARG3(regs));
}

/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */

static int on_connect(struct kprobe *p, struct pt_regs *regs)
{
	struct ev_connect e;
	struct sockaddr *addr = (struct sockaddr *)ARG2(regs);
	u16 family;
	u16 port;

	if (!current->mm)
		return 0;
	if (probe_kernel_read(&family, &addr->sa_family, sizeof(family)))
		return 0;
	if (family != AF_INET_2 && family != AF_INET6_10)
		return 0;

	memset(&e, 0, sizeof(e));
	fill_hdr(&e.h, XIEZHI_KIND_CONN);
	e.family = family == AF_INET_2 ? 4 : 6;

	if (family == AF_INET_2) {
		struct sockaddr_in sa4;
		if (probe_kernel_read(&sa4, addr, sizeof(sa4)))
			return 0;
		port = ntohs(sa4.sin_port);
		memcpy(e.ip, &sa4.sin_addr, 4);
	} else {
		struct sockaddr_in6 sa6;
		if (probe_kernel_read(&sa6, addr, sizeof(sa6)))
			return 0;
		port = ntohs(sa6.sin6_port);
		memcpy(e.ip, &sa6.sin6_addr, 16);
	}
	e.port = port;
	return emit(&e, sizeof(e));
}

/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */

static int on_udp_sendmsg(struct kprobe *p, struct pt_regs *regs)
{
	struct ev_dns e;
	struct sock *sk = (struct sock *)ARG2(regs);
	struct msghdr *msg = (struct msghdr *)ARG3(regs);
	struct sockaddr_in sa4;
	struct sockaddr_in6 sa6;
	u16 family = 0;
	u16 port = 0;
	const void *ip = NULL;
	u8 iplen = 0;
	__be32 ip_copy;
	struct in6_addr ip_copy6;

	if (!current->mm)
		return 0;

	if (msg) {
		struct sockaddr *name = NULL;
		if (probe_kernel_read(&name, &msg->msg_name, sizeof(name)) || !name)
			goto from_sk;
		if (probe_kernel_read(&family, &name->sa_family, sizeof(family)))
			goto from_sk;
		if (family == AF_INET_2 &&
		    !probe_kernel_read(&sa4, name, sizeof(sa4))) {
			port = ntohs(sa4.sin_port);
			ip = &sa4.sin_addr;
			iplen = 4;
		} else if (family == AF_INET6_10 &&
			   !probe_kernel_read(&sa6, name, sizeof(sa6))) {
			port = ntohs(sa6.sin6_port);
			ip = &sa6.sin6_addr;
			iplen = 16;
		}
	}
from_sk:
	/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */
	if (!ip && sk) {
		__be16 dport = 0;

		if (probe_kernel_read(&family, &sk->sk_family, sizeof(family)))
			return 0;
		if (probe_kernel_read(&dport, &sk->sk_dport, sizeof(dport)))
			return 0;
		port = ntohs(dport);
		if (family == AF_INET_2) {
			__be32 daddr;
			if (probe_kernel_read(&daddr, &sk->sk_daddr, sizeof(daddr)))
				return 0;
			ip_copy = daddr;
			ip = &ip_copy;
			iplen = 4;
		} else if (family == AF_INET6_10) {
			struct in6_addr daddr6;
			if (probe_kernel_read(&daddr6, &sk->sk_v6_daddr, sizeof(daddr6)))
				return 0;
			ip_copy6 = daddr6;
			ip = &ip_copy6;
			iplen = 16;
		}
	}
	if (!ip || (port != 53 && port != 5353))
		return 0;

	memset(&e, 0, sizeof(e));
	fill_hdr(&e.h, XIEZHI_KIND_DNS);
	e.family = family == AF_INET_2 ? 4 : 6;
	e.port = port;
	memcpy(e.ip, ip, iplen);
	return emit(&e, sizeof(e));
}

/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */

static int on_mprotect(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long prot = (unsigned long)ARG3(regs);

	if (!current->mm)
		return 0;
	if (!(prot & PROT_EXEC))
		return 0;
	return emit_generic(XIEZHI_KIND_MPROT, (__u64)prot);
}

/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */

static int on_memfd_create(struct kprobe *p, struct pt_regs *regs)
{
	unsigned int flags = (unsigned int)ARG2(regs);

	if (!current->mm)
		return 0;
	return emit_generic(XIEZHI_KIND_MEMFD, (__u64)flags);
}

/* ---- init_module ---- */

static int on_init_module(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long len = (unsigned long)ARG2(regs);

	if (!current->mm)
		return 0;
	return emit_generic(XIEZHI_KIND_MOD_LOAD, (__u64)len);
}

/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */

static int on_commit_creds(struct kprobe *p, struct pt_regs *regs)
{
	struct cred *new = (struct cred *)ARG1(regs);
	kuid_t old_uid, old_euid, new_uid, new_euid;

	if (!current->mm)
		return 0;
	if (!new)
		return 0;

	old_uid = current_uid();
	old_euid = current_euid();
	if (probe_kernel_read(&new_uid, &new->uid, sizeof(new_uid)) ||
	    probe_kernel_read(&new_euid, &new->euid, sizeof(new_euid)))
		return 0;

	if (__kuid_val(old_uid) != 0 && __kuid_val(new_uid) == 0)
		return emit_generic(XIEZHI_KIND_CRED,
				    (__u64)__kuid_val(old_uid) << 32 |
				    (__u32)__kuid_val(new_uid));
	if (__kuid_val(old_euid) != 0 && __kuid_val(new_euid) == 0)
		return emit_generic(XIEZHI_KIND_CRED,
				    (__u64)__kuid_val(old_euid) << 32 |
				    (__u32)__kuid_val(new_euid));
	return 0;
}

/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */

static int on_ptrace(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long request = (unsigned long)ARG1(regs);
	u16 op = (u16)(request & 0xffff);

	if (!current->mm)
		return 0;
	if (op != PTRACE_POKETEXT && op != PTRACE_POKEDATA)
		return 0;
	return emit_generic(XIEZHI_KIND_PTRACE, (__u64)request);
}

/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */

static int on_setsid(struct kprobe *p, struct pt_regs *regs)
{
	if (!current->mm)
		return 0;
	return emit_generic(XIEZHI_KIND_SETSID, 0);
}

/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */

static int on_prctl(struct kprobe *p, struct pt_regs *regs)
{
	int option = (int)ARG1(regs);

	if (!current->mm)
		return 0;
	if (option != PR_SET_NAME)
		return 0;
	return emit_generic(XIEZHI_KIND_PRCTL, (__u64)(unsigned long)PR_SET_NAME);
}

/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */

/* watched dir prefixes */
static int path_prefix_hit(const char *p, size_t len)
{
	static const char *const dirs[] = {
		"/etc/", "/root/.ssh/", "/tmp/", "/var/spool/cron/",
	};
	size_t i, j;

	for (i = 0; i < ARRAY_SIZE(dirs); i++) {
		size_t dl = strlen(dirs[i]);

		if (len >= dl && memcmp(p, dirs[i], dl) == 0)
			return 1;
	}
	if (len >= 6 && memcmp(p, "/home/", 6) == 0) {
		for (j = 6; j + 6 <= len; j++) {
			if (memcmp(p + j, "/.ssh/", 6) == 0)
				return 1;
		}
	}
	return 0;
}

/*
 * Host-true path on 3.10, where struct mount (mnt_parent/mnt_mountpoint)
 * lives in the unexported fs/mount.h and d_absolute_path does not exist.
 * Compose two exported views and keep the longer string:
 *  - d_path: mount-aware, but rooted at the CALLING process's root, so a
 *    chrooted cat on jail/etc/passwd masquerades as "/etc/passwd";
 *  - dentry_path_raw: rooted at the superblock root (immune to chroot),
 *    but blind to mounts, so tmpfs files lose their mountpoint prefix.
 * The two blind spots are disjoint: mount prefixes only lengthen d_path,
 * chroot prefixes only lengthen dentry_path_raw. Equal length (the common
 * case - files on the root fs outside chroot) keeps d_path's stable view.
 */
static char *xz_host_path(const struct path *spath, char *buf, size_t bufsz,
			  char *scratch, size_t scratchsz)
{
	char *a, *b;

	a = d_path(spath, scratch, scratchsz);
	b = dentry_path_raw(spath->dentry, buf, bufsz);
	/* K-7（R8.4 遗留）：d_path 失败（宿主路径超 scratch 160B 的
	 * ENAMETOOLONG 等）不再整体丢事件，降级返回 dentry_path_raw 视角
	 * ——接受其对挂载点前缀盲视（tmpfs 丢挂载前缀）。帧内无视角标记
	 * 字段，消费方无法区分两视角产物，该折衷仅以注释载明（双视角
	 * 盲区互补的权衡）。降级时 b 用 buf/bufsz
	 * （e.filename 128B），非 a 的 scratch。两视角都失败才返回错误、
	 * 由调用方丢事件。 */
	if (IS_ERR(a)) {
		if (!IS_ERR(b))
			return b;
		return a;
	}
	if (IS_ERR(b))
		return a; /* d_path 视角可用时退而求其次 */
	if (strlen(b) > strlen(a))
		return b;
	return a;
}

static int on_file_open(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (struct file *)ARG1(regs);
	struct ev_file e;
	struct path spath;
	char scratch[160];
	char *path_str;
	size_t plen;

	if (!current->mm)
		return 0;
	if (!in_host_mnt_ns())
		return 0;
	if (probe_kernel_read(&spath, &file->f_path, sizeof(spath)))
		return 0;

	memset(&e, 0, sizeof(e));
	path_str = xz_host_path(&spath, e.filename, sizeof(e.filename),
				scratch, sizeof(scratch));
	if (IS_ERR(path_str))
		return 0;
	plen = strnlen(path_str, sizeof(e.filename) - 1);
	memmove(e.filename, path_str, plen + 1);
	if (!plen || !path_prefix_hit(e.filename, plen))
		return 0;

	if (probe_kernel_read(&e.flags, &file->f_flags, sizeof(e.flags)))
		return 0;
	fill_hdr(&e.h, XIEZHI_KIND_FILE_OPEN);
	return emit(&e, sizeof(e));
}

/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */

static size_t read_kstr(char *dst, size_t dstsz, const char *src)
{
	size_t done = 0;

	if (!src)
		return 0;
	while (done + 1 < dstsz) {
		size_t chunk = min_t(size_t, 16, dstsz - 1 - done);
		char *nul;

		if (probe_kernel_read(dst + done, src + done, chunk))
			break;
		nul = memchr(dst + done, 0, chunk);
		if (nul) {
			done += (size_t)(nul - (dst + done));
			break;
		}
		done += chunk;
	}
	dst[done] = '\0';
	return done;
}

/* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */
static int on_umh(struct kprobe *p, struct pt_regs *regs)
{
	struct ev_file e;

	if (!current->mm)
		return 0;

	memset(&e, 0, sizeof(e));
	read_kstr(e.filename, sizeof(e.filename), (const char *)ARG1(regs));
	e.flags = (__u32)ARG4(regs); /* ASCII-only: see xiezhi_frame.h for per-kind detail semantics */
	fill_hdr(&e.h, XIEZHI_KIND_UMH);
	return emit(&e, sizeof(e));
}

struct xiezhi_kprobe xiezhi_hooks[] = {
	{ .name = "execve", .kp = { .symbol_name = "sys_execve", .pre_handler = on_execve } },
	{ .name = "execveat", .optional = 1, .kp = { .symbol_name = "sys_execveat", .pre_handler = on_execveat } },
	{ .name = "connect", .kp = { .symbol_name = "security_socket_connect", .pre_handler = on_connect } },
	{ .name = "dns", .kp = { .symbol_name = "udp_sendmsg", .pre_handler = on_udp_sendmsg } },
	{ .name = "mprotect", .kp = { .symbol_name = "sys_mprotect", .pre_handler = on_mprotect } },
	{ .name = "memfd_create", .optional = 1, .kp = { .symbol_name = "sys_memfd_create", .pre_handler = on_memfd_create } },
	{ .name = "init_module", .kp = { .symbol_name = "sys_init_module", .pre_handler = on_init_module } },
	{ .name = "commit_creds", .kp = { .symbol_name = "commit_creds", .pre_handler = on_commit_creds } },
	{ .name = "ptrace", .kp = { .symbol_name = "sys_ptrace", .pre_handler = on_ptrace } },
	{ .name = "setsid", .kp = { .symbol_name = "sys_setsid", .pre_handler = on_setsid } },
	{ .name = "prctl", .kp = { .symbol_name = "sys_prctl", .pre_handler = on_prctl } },
	{ .name = "file_open", .kp = { .symbol_name = "security_file_open", .pre_handler = on_file_open } },
	{ .name = "umh", .kp = { .symbol_name = "call_usermodehelper", .pre_handler = on_umh } },
};
const int xiezhi_hooks_count = ARRAY_SIZE(xiezhi_hooks);

int xiezhi_collect_init(void)
{
	int ret;

	/* kallsyms_lookup_name is module-unexported on >=5.7; without it the
	 * container filter degrades to emit (init_mnt_ns stays NULL) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
	{
		struct nsproxy *nsp =
			(struct nsproxy *)kallsyms_lookup_name("init_nsproxy");

		if (nsp)
			init_mnt_ns = nsp->mnt_ns;
	}
#endif
	ret = xiezhi_ring_init(&ring, XIEZHI_RING_BYTES);
	if (ret)
		return ret;
	ret = xiezhi_trace_init(&ring);
	if (ret) {
		xiezhi_ring_destroy(&ring);
		return ret;
	}
	return 0;
}

void xiezhi_collect_exit(void)
{
	xiezhi_trace_exit();
	xiezhi_ring_destroy(&ring);
}
