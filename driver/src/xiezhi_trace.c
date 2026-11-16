#include "xiezhi_trace.h"

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define PROC_DIR "xiezhi"
#define PROC_ENTRY "endpoint"

static struct xiezhi_ring *the_ring;
static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_entry;

/*
 * read 语义：一次调用尽量多拷整帧到用户态（上限 8KB）；
 * 无数据返回 0（非阻塞式轮询由用户态 poll 驱动）。
 * 锁内 ring→scratch，锁外 scratch→user（copy_to_user 不可持自旋锁）。
 */
static ssize_t xiezhi_proc_read(struct file *file, char __user *buf,
			      size_t count, loff_t *ppos)
{
	void *scratch;
	u32 got;
	unsigned char *kv = file->private_data;

	if (!kv)
		return -EIO;
	if (count == 0)
		return 0;

	scratch = kmalloc(min_t(size_t, count, 8192), GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;

	got = xiezhi_ring_take(the_ring, scratch, min_t(size_t, count, 8192));
	if (got == 0) {
		kfree(scratch);
		return 0;
	}
	if (copy_to_user(buf, scratch, got)) {
		kfree(scratch);
		return -EFAULT;
	}
	kfree(scratch);
	return got;
}

static unsigned int xiezhi_proc_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &the_ring->wq, wait);
	if (xiezhi_ring_has_data(the_ring))
		return POLLIN | POLLRDNORM;
	return 0;
}

static int xiezhi_proc_open(struct inode *inode, struct file *file)
{
	/* 每个打开实例的读游标在环级共享（v0 单读者设计，多余读者只做旁路观测） */
	file->private_data = (void *)1;
	return 0;
}

static int xiezhi_proc_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations xiezhi_proc_fops = {
	.owner = THIS_MODULE,
	.open = xiezhi_proc_open,
	.read = xiezhi_proc_read,
	.poll = xiezhi_proc_poll,
	.release = xiezhi_proc_release,
};

int xiezhi_trace_init(struct xiezhi_ring *r)
{
	the_ring = r;
	proc_dir = proc_mkdir(PROC_DIR, NULL);
	if (!proc_dir)
		return -ENOMEM;
	proc_entry = proc_create(PROC_ENTRY, 0600, proc_dir, &xiezhi_proc_fops);
	if (!proc_entry) {
		remove_proc_entry(PROC_DIR, NULL);
		return -ENOMEM;
	}
	return 0;
}

void xiezhi_trace_exit(void)
{
	if (proc_entry)
		remove_proc_entry(PROC_ENTRY, proc_dir);
	if (proc_dir)
		remove_proc_entry(PROC_DIR, NULL);
}
