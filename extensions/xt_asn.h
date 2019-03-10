/* ipt_asn.h header file for libipt_asn.c and ipt_asn.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Copyright (c) 2004, 2005, 2006, 2007, 2008
 *
 * Samuel Jean
 * Nicolas Bouliane
 *
 * D. Stussy - 2019 - Repurposed xt_geoip.h for ASN use.
 */
#ifndef _LINUX_NETFILTER_XT_ASN_H
#define _LINUX_NETFILTER_XT_ASN_H 1

enum {
	XT_ASN_SRC = 1 << 0,	/* Perform check on Source IP */
	XT_ASN_DST = 1 << 1,	/* Perform check on Destination IP */
	XT_ASN_INV = 1 << 2,	/* Negate the condition */

	XT_ASN_MAX = 15,	/* Maximum of countries */
};

/* Yup, an address range will be passed in with host-order */
struct asn_subnet4 {
	__u32 begin;
	__u32 end;
};

struct asn_subnet6 {
	struct in6_addr begin, end;
};

struct asn_number_user {
	aligned_u64 subnets;
	__u32 count;
	__u32 asn;
};

struct asn_number_kernel;

union asn_number_group {
	aligned_u64 user; /* struct asn_number_user * */
	struct asn_number_kernel *kernel;
};

struct xt_asn_match_info {
	__u32 asn[XT_ASN_MAX];
	__u8 flags;
	__u8 count;

	/* Used internally by the kernel */
	union asn_number_group mem[XT_ASN_MAX];
};

#endif /* _LINUX_NETFILTER_XT_ASN_H */
