#pragma once

enum {
	CONDITION_NAME_LEN = 31,
};

struct xt_condition_mtinfo {
	char name[CONDITION_NAME_LEN];
	__u8 invert;

	/* Used internally by the kernel */
	void *condvar __attribute__((aligned(8)));
};
