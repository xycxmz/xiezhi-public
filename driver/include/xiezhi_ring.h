#ifndef _XIEZHI_RING_H
#define _XIEZHI_RING_H

#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/types.h>

/*
 * v0 全局单环（spinlock + 覆盖模式 + 丢包计数）。
 * 写侧：kprobe/原子上下文，只允许 spin_lock_irqsave + memcpy，禁睡眠。
 * 读侧：/proc 读出，锁内拷到调用方提供的内核暂存区，锁外再 copy_to_user。
 * ftrace ring_buffer 移植（per-CPU、两阶段提交）在 M2 驱动加固替换本实现。
 */
struct xiezhi_ring {
	spinlock_t lock;
	unsigned char *buf;
	u32 size;      /* 2 的幂 */
	u64 head;      /* 写游标（字节，单调） */
	u64 tail;      /* 读游标（字节，单调），覆盖时按整帧跳 */
	u64 dropped;
	wait_queue_head_t wq;
};

int xiezhi_ring_init(struct xiezhi_ring *r, u32 size_bytes);
void xiezhi_ring_destroy(struct xiezhi_ring *r);

/* 原子上下文安全。data 长度不含帧头，函数内部补 4 字节长度头。 */
void xiezhi_ring_put(struct xiezhi_ring *r, const void *data, u32 data_len);

/* 锁内快照：把最多 buf_cap 字节的未读数据拷到 dst，返回实际字节数，并推进 tail。 */
u32 xiezhi_ring_take(struct xiezhi_ring *r, void *dst, u32 buf_cap);

static inline int xiezhi_ring_has_data(struct xiezhi_ring *r)
{
	return r->head != r->tail;
}

#endif /* _XIEZHI_RING_H */
