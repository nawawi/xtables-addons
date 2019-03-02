/*
 * Protocol modification target for IP tables
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <net/checksum.h>


#include <linux/netfilter/x_tables.h>
#include "xt_PROTO.h"

MODULE_AUTHOR("Shanker Wang <i@innull.com>");
MODULE_DESCRIPTION("Xtables: Protocol field modification target");
MODULE_LICENSE("GPL");

static unsigned int
proto_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr *iph;
	const struct xt_PROTO_info *info = par->targinfo;
	int new_proto;

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;

	iph = ip_hdr(skb);

	new_proto = iph->protocol;
	if(info->mode & (1 << XT_PROTO_SET)){
		new_proto = info->proto;
	}
	if (new_proto != iph->protocol) {
		csum_replace2(&iph->check, htons(iph->protocol & 0xff),
					   htons(new_proto & 0xff));
		iph->protocol = new_proto;
	}

	return XT_CONTINUE;
}

static unsigned int
proto_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct ipv6hdr *ip6h;
	const struct xt_PROTO_info *info = par->targinfo;
	u8 *nexthdr; 
	unsigned int hdr_offset;
	__be16 *fp;

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;

	ip6h = ipv6_hdr(skb);
	nexthdr = &ip6h->nexthdr;

	hdr_offset = sizeof(struct ipv6hdr);

	for(;;){
		struct ipv6_opt_hdr _opthdr, *opthp;
		unsigned int hdrlen;
		unsigned short _frag_off;
		if ((!ipv6_ext_hdr(*nexthdr)) || *nexthdr == NEXTHDR_NONE) {
			break;
		}
		opthp = skb_header_pointer(skb, skb_network_offset(skb) + hdr_offset, sizeof(_opthdr), &_opthdr);
		if(!opthp){
			return NF_DROP;
		}
		if(*nexthdr == NEXTHDR_FRAGMENT){
			if(info->mode & (1 << XT_PROTO_STOP_AT_FRAG)){
				break;
			}
			fp = skb_header_pointer(skb,
						skb_network_offset(skb) + hdr_offset + 
							offsetof(struct frag_hdr,
							       frag_off),
						sizeof(_frag_off),
						&_frag_off);
			if (!fp)
				return NF_DROP;
			_frag_off = ntohs(*fp) & ~0x7;
			if(_frag_off){ // if the packet is not the first fragment
				if ((!ipv6_ext_hdr(opthp->nexthdr)) || opthp->nexthdr == NEXTHDR_NONE || 
					((info->mode & (1 << XT_PROTO_STOP_AT_AUTH)) && opthp->nexthdr == NEXTHDR_AUTH)
				) {
					nexthdr = &((struct ipv6_opt_hdr*)(skb_network_header(skb) + hdr_offset))->nexthdr;
					break;
				}else{
					return XT_CONTINUE;
				}
			}
			hdrlen = 8;
		}else if(*nexthdr == NEXTHDR_AUTH){
			if(info->mode & (1 << XT_PROTO_STOP_AT_AUTH)){
				break;
			}
			hdrlen = (opthp->hdrlen + 2) << 2;
		}else{
			hdrlen = ipv6_optlen(opthp);
		}
		nexthdr = &((struct ipv6_opt_hdr*)(skb_network_header(skb) + hdr_offset))->nexthdr;
		hdr_offset += hdrlen;
	}
	
	if(info->mode & (1 << XT_PROTO_SET)){
		*nexthdr = info->proto;
	}

	return XT_CONTINUE;
}

static int proto_tg_check(const struct xt_tgchk_param *par)
{
	const struct xt_PROTO_info *info = par->targinfo;

	if ((info->mode & (1 << XT_PROTO_SET)) == 0){
		pr_info_ratelimited("Did not specify any proto to set\n");
		return -EINVAL;
	}
	if ((par->family != NFPROTO_IPV6) && ((info->mode & ((1 << XT_PROTO_STOP_AT_FRAG) | (1 << XT_PROTO_STOP_AT_AUTH))) != 0)){
		pr_info_ratelimited("Must not specify stop-at-frag and stop-at-auth on non-ipv6 targets\n"); 
		return -EPROTOTYPE;
	}
	return 0;
}

static struct xt_target proto_tg_reg[] __read_mostly = {
	{
		.name       = "PROTO",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = proto_tg,
		.targetsize = sizeof(struct xt_PROTO_info),
		.table      = "mangle",
		.checkentry = proto_tg_check,
		.me         = THIS_MODULE,
	},
	{
		.name       = "PROTO",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.target     = proto_tg6,
		.targetsize = sizeof(struct xt_PROTO_info),
		.table      = "mangle",
		.checkentry = proto_tg_check,
		.me         = THIS_MODULE,
	},
};

static int __init proto_tg_init(void)
{
	return xt_register_targets(proto_tg_reg, ARRAY_SIZE(proto_tg_reg));
}

static void __exit proto_tg_exit(void)
{
	xt_unregister_targets(proto_tg_reg, ARRAY_SIZE(proto_tg_reg));
}

module_init(proto_tg_init);
module_exit(proto_tg_exit);
MODULE_ALIAS("ipt_PROTO");
MODULE_ALIAS("ip6t_PROTO");

