#ifndef _XIEZHI_KPROBE_H
#define _XIEZHI_KPROBE_H

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/printk.h>

/*
 * kprobe 登记表。hook 项在 xiezhi_hooks.c 静态定义，注册失败按 LIFO 回退已成功项。
 * handler 约束：pre/post 上下文禁睡眠，只允许 spinlock 与原子操作；
 * 用户态内存一律 copy_from_user 系；新增内核 API 调用前先核对目标内核版本语义。
 */
struct xiezhi_kprobe {
	const char *name;   /* 登记名，仅用于日志 */
	int optional;       /* 1 = symbol-missing degrades this hook only */
	int registered;     /* 1 = currently registered */
	struct kprobe kp;
};

int xiezhi_kprobes_init(void);
void xiezhi_kprobes_exit(void);

#endif /* _XIEZHI_KPROBE_H */
