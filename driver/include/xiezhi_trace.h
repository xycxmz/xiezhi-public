#ifndef _XIEZHI_TRACE_H
#define _XIEZHI_TRACE_H

#include "xiezhi_ring.h"

/* /proc/xiezhi/endpoint 数据面：read（拷出整帧批）+ poll。 */
int xiezhi_trace_init(struct xiezhi_ring *r);
void xiezhi_trace_exit(void);

#endif /* _XIEZHI_TRACE_H */
