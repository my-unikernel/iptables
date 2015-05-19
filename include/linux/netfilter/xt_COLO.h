#ifndef _XT_COLO_TARGET_H
#define _XT_COLO_TARGET_H

#include <linux/types.h>

struct xt_colo_primary_info {
	__u32			index;
	char forward_dev[256];

	/* for kernel module internal use only */
	struct colo_primary *colo __attribute__((aligned(8)));
};

struct xt_colo_secondary_info {
	__u32			index;

	/* for kernel module internal use only */
	struct colo_secondary *colo __attribute__((aligned(8)));
};
#endif
