#ifndef _XTABLES_COMPAT_H
#define _XTABLES_COMPAT_H 1

#include <linux/kernel.h>
#include <linux/version.h>
#include "compat_skbuff.h"
#include "compat_xtnu.h"

#define DEBUGP Use__pr_debug__instead

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
#	warning Kernels below 4.0 not supported.
#endif

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
#	if !defined(CONFIG_NF_CONNTRACK_MARK)
#		warning You have CONFIG_NF_CONNTRACK enabled, but CONFIG_NF_CONNTRACK_MARK is not (please enable).
#	endif
#	include <net/netfilter/nf_conntrack.h>
#else
#	warning You need CONFIG_NF_CONNTRACK.
#endif

#if !defined(NIP6) && !defined(NIP6_FMT)
#	define NIP6(addr) \
		ntohs((addr).s6_addr16[0]), \
		ntohs((addr).s6_addr16[1]), \
		ntohs((addr).s6_addr16[2]), \
		ntohs((addr).s6_addr16[3]), \
		ntohs((addr).s6_addr16[4]), \
		ntohs((addr).s6_addr16[5]), \
		ntohs((addr).s6_addr16[6]), \
		ntohs((addr).s6_addr16[7])
#	define NIP6_FMT "%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx"
#endif
#if !defined(NIPQUAD) && !defined(NIPQUAD_FMT)
#	define NIPQUAD(addr) \
		((const unsigned char *)&addr)[0], \
		((const unsigned char *)&addr)[1], \
		((const unsigned char *)&addr)[2], \
		((const unsigned char *)&addr)[3]
#	define NIPQUAD_FMT "%hhu.%hhu.%hhu.%hhu"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
#	define ip6_local_out(xnet, xsk, xskb) ip6_local_out(xskb)
#	define ip6_route_me_harder(xnet, xskb) ip6_route_me_harder(xskb)
#	define ip_local_out(xnet, xsk, xskb) ip_local_out(xskb)
#	define ip_route_me_harder(xnet, xskb, xaddrtype) ip_route_me_harder((xskb), (xaddrtype))
#endif

static inline struct net *par_net(const struct xt_action_param *par)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	return par->state->net;
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	return par->net;
#else
	return dev_net((par->in != NULL) ? par->in : par->out);
#endif
#endif
}

#ifndef NF_CT_ASSERT
#	define NF_CT_ASSERT(x)	WARN_ON(!(x))
#endif

#endif /* _XTABLES_COMPAT_H */
