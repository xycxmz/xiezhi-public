#ifndef _XIEZHI_HOOKS_H
#define _XIEZHI_HOOKS_H

#include "xiezhi_kprobe.h"

/* hooks 表由 xiezhi_hooks.c 定义，注册/注销见 xiezhi_kprobes.c */
extern struct xiezhi_kprobe xiezhi_hooks[];
extern const int xiezhi_hooks_count;

/* 环+数据面生命周期（ring/proc 归 xiezhi_hooks.c 所有） */
int xiezhi_collect_init(void);
void xiezhi_collect_exit(void);

#endif /* _XIEZHI_HOOKS_H */
