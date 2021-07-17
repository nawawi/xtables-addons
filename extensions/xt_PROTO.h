/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Protocol modification module for IP tables */
#pragma once
#include <linux/types.h>

enum {
	XT_PROTO_SET = 0,
	XT_PROTO_STOP_AT_FRAG = 1,
	XT_PROTO_STOP_AT_AUTH = 2
};

struct xt_PROTO_info {
	__u8	mode;
	__u8	proto;
};
