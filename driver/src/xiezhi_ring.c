#include "xiezhi_ring.h"

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>

#define FRAME_HDR_LEN 4

int xiezhi_ring_init(struct xiezhi_ring *r, u32 size_bytes)
{
	/* 向上取 2 的幂，最低 64KB */
	u32 size = 65536;
	while (size < size_bytes)
		size <<= 1;

	r->buf = kmalloc(size, GFP_KERNEL);
	if (!r->buf)
		return -ENOMEM;
	r->size = size;
	r->head = 0;
	r->tail = 0;
	r->dropped = 0;
	spin_lock_init(&r->lock);
	init_waitqueue_head(&r->wq);
	return 0;
}

void xiezhi_ring_destroy(struct xiezhi_ring *r)
{
	kfree(r->buf);
	r->buf = NULL;
}

static inline u32 pos(struct xiezhi_ring *r, u64 counter)
{
	return counter & (r->size - 1);
}

/* 覆盖最旧数据：按帧边界推进 tail（每帧头部 4 字节是总长） */
static void skip_oldest_frame(struct xiezhi_ring *r)
{
	u32 total;
	u32 off = pos(r, r->tail);

	if (off + FRAME_HDR_LEN <= r->size)
		memcpy(&total, r->buf + off, FRAME_HDR_LEN);
	else {
		/* 帧头跨环回绕 */
		u8 tmp[FRAME_HDR_LEN];
		u32 first = r->size - off;
		memcpy(tmp, r->buf + off, first);
		memcpy(tmp + first, r->buf, FRAME_HDR_LEN - first);
		memcpy(&total, tmp, FRAME_HDR_LEN);
	}
	if (total < FRAME_HDR_LEN || total > 1024) {
		/* 尾部落在被部分覆盖的帧上（不应发生，防御）：整环重置 */
		r->tail = r->head;
		return;
	}
	r->tail += total;
}

static inline void ring_copy_in(struct xiezhi_ring *r, u64 counter,
				const void *src, u32 len)
{
	u32 off = pos(r, counter);
	u32 first = r->size - off;
	if (first >= len) {
		memcpy(r->buf + off, src, len);
		return;
	}
	memcpy(r->buf + off, src, first);
	memcpy(r->buf, (const unsigned char *)src + first, len - first);
}

void xiezhi_ring_put(struct xiezhi_ring *r, const void *data, u32 data_len)
{
	u32 total = data_len + FRAME_HDR_LEN;
	unsigned long flags;
	u32 hdr = total;

	spin_lock_irqsave(&r->lock, flags);

	while (r->head - r->tail + total > r->size) {
		r->dropped++;
		skip_oldest_frame(r);
		if (r->tail == r->head)
			break;
	}

	ring_copy_in(r, r->head, &hdr, FRAME_HDR_LEN);
	ring_copy_in(r, r->head + FRAME_HDR_LEN, data, data_len);
	r->head += total;

	spin_unlock_irqrestore(&r->lock, flags);

	wake_up_interruptible(&r->wq);
}

u32 xiezhi_ring_take(struct xiezhi_ring *r, void *dst, u32 buf_cap)
{
	u32 copied = 0;
	unsigned long flags;

	spin_lock_irqsave(&r->lock, flags);
	while (r->tail != r->head && copied + FRAME_HDR_LEN <= buf_cap) {
		u32 total, off, first;
		u32 remain = buf_cap - copied;

		off = pos(r, r->tail);
		if (off + FRAME_HDR_LEN <= r->size) {
			memcpy(&total, r->buf + off, FRAME_HDR_LEN);
		} else {
			u8 tmp[FRAME_HDR_LEN];
			first = r->size - off;
			memcpy(tmp, r->buf + off, first);
			memcpy(tmp + first, r->buf, FRAME_HDR_LEN - first);
			memcpy(&total, tmp, FRAME_HDR_LEN);
		}
		if (total < FRAME_HDR_LEN || total > 1024) {
			r->tail = r->head; /* 流损坏，防御性重置 */
			break;
		}
		if (total > remain)
			break; /* 放不下整帧，留给下次 */

		if (off + total <= r->size) {
			memcpy((unsigned char *)dst + copied, r->buf + off, total);
		} else {
			first = r->size - off;
			memcpy((unsigned char *)dst + copied, r->buf + off, first);
			memcpy((unsigned char *)dst + copied + first, r->buf, total - first);
		}
		r->tail += total;
		copied += total;
	}
	spin_unlock_irqrestore(&r->lock, flags);
	return copied;
}
