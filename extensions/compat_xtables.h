#ifndef _XTABLES_COMPAT_H
#define _XTABLES_COMPAT_H 1

#include <linux/kernel.h>
#include <linux/version.h>
#include "compat_skbuff.h"
#include "compat_xtnu.h"

#define DEBUGP Use__pr_debug__instead

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
#	warning Kernels below 3.7 not supported.
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
#	define prandom_u32() random32()
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
#	define NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#endif
#if !defined(NIPQUAD) && !defined(NIPQUAD_FMT)
#	define NIPQUAD(addr) \
		((const unsigned char *)&addr)[0], \
		((const unsigned char *)&addr)[1], \
		((const unsigned char *)&addr)[2], \
		((const unsigned char *)&addr)[3]
#	define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
static inline struct inode *file_inode(struct file *f)
{
	return f->f_path.dentry->d_inode;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
static inline void proc_set_user(struct proc_dir_entry *de,
    typeof(de->uid) uid, typeof(de->gid) gid)
{
	de->uid = uid;
	de->gid = gid;
}

static inline void *PDE_DATA(struct inode *inode)
{
	return PDE(inode)->data;
}

static inline void proc_remove(struct proc_dir_entry *de)
{
	if (de != NULL)
		remove_proc_entry(de->name, de->parent);
}
#endif

#endif /* _XTABLES_COMPAT_H */
