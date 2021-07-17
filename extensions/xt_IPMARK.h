#pragma once

enum {
	XT_IPMARK_SRC,
	XT_IPMARK_DST,
};

struct xt_ipmark_tginfo {
	__u32 andmask;
	__u32 ormask;
	__u8 selector;
	__u8 shift;
};
