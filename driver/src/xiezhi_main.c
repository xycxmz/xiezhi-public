#include <linux/module.h>

#include "xiezhi_hooks.h"
#include "xiezhi_kprobe.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("xiezhi kernel event collector (kprobe, CentOS 7 / 3.10 first)");
MODULE_VERSION("0.1.0");

static int __init xiezhi_driver_init(void)
{
	int ret;

	ret = xiezhi_collect_init();
	if (ret)
		return ret;
	ret = xiezhi_kprobes_init();
	if (ret) {
		xiezhi_collect_exit();
		return ret;
	}
	pr_info("xiezhi: driver up (/proc/xiezhi/endpoint)\n");
	return 0;
}

static void __exit xiezhi_driver_exit(void)
{
	xiezhi_kprobes_exit();
	xiezhi_collect_exit();
	pr_info("xiezhi: driver down\n");
}

module_init(xiezhi_driver_init);
module_exit(xiezhi_driver_exit);
