#ifndef _XTABLES_COMPAT_H
#define _XTABLES_COMPAT_H 1

#include <linux/kernel.h>
#include <linux/version.h>
#include "compat_skbuff.h"
#include "compat_xtnu.h"

#define DEBUGP Use__pr_debug__instead

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
#	warning Kernels below 4.15 not supported.
#endif

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
#	if !defined(CONFIG_NF_CONNTRACK_MARK)
#		warning You have CONFIG_NF_CONNTRACK enabled, but CONFIG_NF_CONNTRACK_MARK is not (please enable).
#	endif
#	include <net/netfilter/nf_conntrack.h>
#else
#	warning You need CONFIG_NF_CONNTRACK.
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || \
    LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 9) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#else
#	define ip_route_me_harder(xnet, xsk, xskb, xaddrtype) ip_route_me_harder((xnet), (xskb), (xaddrtype))
#	define ip6_route_me_harder(xnet, xsk, xskb) ip6_route_me_harder((xnet), (xskb))
#endif

static inline struct net *par_net(const struct xt_action_param *par)
{
	return par->state->net;
}

#ifndef NF_CT_ASSERT
#	define NF_CT_ASSERT(x)	WARN_ON(!(x))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
#	define proc_ops file_operations
#	define proc_open open
#	define proc_read read
#	define proc_write write
#	define proc_lseek llseek
#	define proc_release release
#endif

#endif /* _XTABLES_COMPAT_H */
