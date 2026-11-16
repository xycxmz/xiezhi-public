#include "xiezhi_kprobe.h"
#include "xiezhi_hooks.h"

/*
 * R1.4 optional probe: symbol missing on old kernels (e.g. sys_execveat and
 * sys_memfd_create are 3.10.0-693+ backports) should degrade that hook only,
 * not reject the entire driver. Mandatory hooks (execve/connect/dns) still
 * fail the whole load via goto unwind.
 */
int xiezhi_kprobes_init(void)
{
	int i, ret, failed_optional = 0;

	for (i = 0; i < xiezhi_hooks_count; i++) {
		ret = register_kprobe(&xiezhi_hooks[i].kp);
		if (ret) {
			if (xiezhi_hooks[i].optional) {
				pr_warn("xiezhi: optional kprobe %s unavailable "
					"(kernel likely older than symbol), degrading\n",
					xiezhi_hooks[i].name);
				xiezhi_hooks[i].registered = 0;
				failed_optional++;
				continue;
			}
			pr_err("xiezhi: register kprobe %s failed: %d\n",
			       xiezhi_hooks[i].name, ret);
			goto unwind;
		}
		xiezhi_hooks[i].registered = 1;
		pr_info("xiezhi: kprobe %s -> %s\n",
			xiezhi_hooks[i].name, xiezhi_hooks[i].kp.symbol_name);
	}
	if (failed_optional)
		pr_info("xiezhi: %d optional kprobes degraded\n", failed_optional);
	return 0;

unwind:
	while (i-- > 0) {
		if (xiezhi_hooks[i].registered)
			unregister_kprobe(&xiezhi_hooks[i].kp);
	}
	return ret;
}

void xiezhi_kprobes_exit(void)
{
	int i;

	for (i = xiezhi_hooks_count - 1; i >= 0; i--) {
		if (xiezhi_hooks[i].registered)
			unregister_kprobe(&xiezhi_hooks[i].kp);
	}
	pr_info("xiezhi: all kprobes unregistered\n");
}
