#ifndef _XIEZHI_FRAME_H
#define _XIEZHI_FRAME_H

#include <linux/types.h>

/*
 * M1-B v0M5  kind 6-14  ev_generic/ev_file
 * - [u32 ][ev ]
 * - ev  eBPF  bpf/events.bpf.c Go 
 *   agent/internal/collector/{ebpf,lkm} pad
 * - M5  LKM Go lkm frameSizes/decodeFrame
 *   eBPF 
 */

#define XIEZHI_KIND_FORK   1
#define XIEZHI_KIND_EXEC   2
#define XIEZHI_KIND_EXIT   3
#define XIEZHI_KIND_CONN   4
#define XIEZHI_KIND_DNS    5
#define XIEZHI_KIND_MPROT      6  /* mprotect  PROT_EXEC */
#define XIEZHI_KIND_MEMFD      7  /* memfd_create */
#define XIEZHI_KIND_MOD_LOAD   8  /* init_module */
#define XIEZHI_KIND_CRED       9  /* commit_creds  root -> root */
#define XIEZHI_KIND_PTRACE     10 /* POKETEXT/POKEDATA */
#define XIEZHI_KIND_SETSID     11
#define XIEZHI_KIND_PRCTL      12 /* PR_SET_NAME */
#define XIEZHI_KIND_FILE_OPEN  13 /*  */
#define XIEZHI_KIND_UMH        14 /* call_usermodehelper */

struct ev_hdr {
	__u32 kind;
	__u32 pid;
	__u32 ppid;
	__u32 pad;
	__u64 ts_ns;
};

struct ev_exec {
	struct ev_hdr h;
	char comm[16];
	char filename[128];
	char argv[256];
	__u32 argv_len;
	__u32 uid;
	__u64 start_ticks; /* task->start_timeM4session pid  */
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
}; /* sizeof  48Go  4  */

/*
 * ev_generic.detail  kind Go  proto 
 * MPROT=prot MEMFD=flagsMOD_LOAD= len
 * CRED=old_uid<<32|new_uid uid/euid
 * PTRACE= requestSETSID=0PRCTL=PR_SET_NAME(15)
 */
struct ev_generic {
	struct ev_hdr h;
	__u64 detail;
};

/*
 * ev_file.flags  kind FILE_OPEN=file->f_flags
 * UMH=call_usermodehelper  wait UMH_*filename  NUL 
 */
struct ev_file {
	struct ev_hdr h;
	char filename[128];
	__u32 flags;
	__u32 pad;
};

#endif /* _XIEZHI_FRAME_H */
