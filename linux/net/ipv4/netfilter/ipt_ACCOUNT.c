/*
 * This is a module which is used for counting packets.
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/spinlock.h>
#include <net/icmp.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <linux/netfilter_ipv4/ip_tables.h>

struct in_device;
#include <net/route.h>
#include <linux/netfilter_ipv4/ipt_ACCOUNT.h>

//#if 0
#define DEBUGP printk
//#else
//#define DEBUGP(format, args...)
//#endif

struct ipt_account_table *ipt_account_tables = NULL;
struct ipt_account_handle *ipt_account_handles = NULL;

static spinlock_t ipt_account_lock = SPIN_LOCK_UNLOCKED;

static unsigned int
ipt_account_target(struct sk_buff **pskb,
    unsigned int hooknum,
    const struct net_device *in,
    const struct net_device *out,
    const void *targinfo,
    void *userinfo)
{
    spin_lock_bh(&ipt_account_lock);
    spin_unlock_bh(&ipt_account_lock);

    return IPT_CONTINUE;
}

/* Recursive free of all data structures */
void ipt_account_data_free(void *data, unsigned char netsize)
{
    // Empty data set
    if (!data)
        return;
        
    // Free for 8 bit network. Special: 0.0.0.0/0
    if (netsize >= 24 || netsize == 0)
    {
        kfree(data);
        data = NULL;
        return;
    }
    
    // Free for 16 bit network
    if (netsize >= 16)
    {
        struct ipt_account_mask_16 *mask_16 = (struct ipt_account_mask_16 *)data;
        unsigned char b;
        for (b=0; b < 255; b++)
        {
            if (mask_16->mask_24[b] != 0)
            {
                kfree(mask_16->mask_24[b]);
                mask_16->mask_24[b] = NULL;
            }
        }
        kfree(data);
        data = NULL;
        return;
    } 
   
    // Free for 24 bit network
    if (netsize >= 8)
    {
        unsigned char a, b;
        for (a=0; a < 255; a++)
        {
            if (((struct ipt_account_mask_8 *)data)->mask_16[a])
            {
                struct ipt_account_mask_16 *mask_16 = (struct ipt_account_mask_16*)((struct ipt_account_mask_8 *)data)->mask_16[a];
                for (b=0; b < 255; b++)
                {
                    if (mask_16->mask_24[b]) {
                        kfree(mask_16->mask_24[b]);
                        mask_16->mask_24[b] = NULL;
                    }
                }
                kfree(mask_16);
                mask_16 = NULL;
            }
        }
        kfree(data);
        data = NULL;
        return;
    }
    
    printk("ACCOUNT: ipt_account_data_free called with broken netsize: %d\n", netsize);
    return;
}

/* Look for existing table / insert new one. Return internal ID or -1 on error */
int ipt_account_table_insert(char *name, unsigned int ip, unsigned int netmask)
{
    unsigned int i;

    DEBUGP("ACCOUNT: ipt_account_table_insert: %s, %u/%u\n", name, ip, netmask);

    // Look for existing table
    for (i = 0; i < ACCOUNT_MAX_TABLES; i++)
    {
        if (strcmp(ipt_account_tables[i].name, name) == 0)
        {
            DEBUGP("ACCOUT: Found existing slot: %d - %u/%u\n", i, ipt_account_tables[i].ip, ipt_account_tables[i].netmask);
            
            if (ipt_account_tables[i].ip != ip || ipt_account_tables[i].netmask != netmask)
            {
                printk("ACCOUNT: Table %s found, but IP/netmask mismatch. IP/netmask found: %u/%u\n",
                        name, ipt_account_tables[i].ip, ipt_account_tables[i].netmask);
                return -1;
            }

            ipt_account_tables[i].refcount++;
            DEBUGP("ACCOUNT: Refcount: %d\n", ipt_account_tables[i].refcount);
            return i;
        }
    }

    // Insert new table
    for (i = 0; i < ACCOUNT_MAX_TABLES; i++)
    {
        // Found free slot
        if (ipt_account_tables[i].name[0] == 0)
        {
            DEBUGP("ACCOUNT: Found free slot: %d\n", i);
        
            strncpy (ipt_account_tables[i].name, name, ACCOUNT_TABLE_NAME_LEN-1);
            
            ipt_account_tables[i].ip = ip;
            ipt_account_tables[i].netmask = netmask;
            
            // calculate netsize
            unsigned int j, calc_mask;
            calc_mask = htonl(netmask);
            for (j = 31; j > 0; j--)
            {
                if (calc_mask&(1<<j))
                    ipt_account_tables[i].netsize++;
                else
                    break;
            }
            printk("ACCOUNT: calculated netsize: %u\n", ipt_account_tables[i].netsize);
                        
            ipt_account_tables[i].refcount++;
            if (!(ipt_account_tables[i].data = (void *)get_zeroed_page(GFP_KERNEL)))
            {
                printk("ACCOUNT: Out of memory for data of table: %s\n", name);
                memset(&ipt_account_tables[i], 0, sizeof(struct ipt_account_table));
                return -1;
            }
            return i;
        }
    }
        
    // No free slot found
    printk("ACCOUNT: No free table slot found (max: %d). Please increase ACCOUNT_MAX_TABLES.\n", ACCOUNT_MAX_TABLES);
    return -1;
}

static int ipt_account_checkentry(const char *tablename,
    const struct ipt_entry *e,
    void *targinfo,
    unsigned int targinfosize,
    unsigned int hook_mask)
{
    struct ipt_account_info *info = targinfo;
    
    if (targinfosize != IPT_ALIGN(sizeof(struct ipt_account_info))) {
        DEBUGP("ACCOUNT: targinfosize %u != %u\n",
                targinfosize, IPT_ALIGN(sizeof(struct ipt_account_info)));
        return 0;
    }

    int table_nr = ipt_account_table_insert(info->table_name, info->net_ip, info->net_mask);
    if (table_nr == -1)
    {
        printk("ACCOUNT: Table insert problem. Aborting\n");
        return 0;
    }

    // Table nr caching so we don't have to do an extra string compare for every packet
    info->table_nr = table_nr;
    
    return 1;
}

static struct ipt_target ipt_account_reg
= { { NULL, NULL }, "ACCOUNT", ipt_account_target, ipt_account_checkentry, NULL, 
    THIS_MODULE };

static int __init init(void)
{
    if (!(ipt_account_tables = kmalloc(ACCOUNT_MAX_TABLES, sizeof(struct ipt_account_table))))
    {
            printk("ACCOUNT: Out of memory allocating account_tables structure");
            return -EINVAL;
    }
    memset(ipt_account_tables, 0, sizeof(struct ipt_account_table));
                            
    if (!(ipt_account_handles = kmalloc(ACCOUNT_MAX_HANDLES, sizeof(struct ipt_account_handle))))
    {
            printk("ACCOUNT: Out of memory allocating account_handles structure");
            kfree (ipt_account_tables);
            ipt_account_tables = NULL;
            return -EINVAL;
    }
    memset(ipt_account_handles, 0, sizeof(struct ipt_account_handle));
    
    if (ipt_register_target(&ipt_account_reg))
            return -EINVAL;

    return 0;
}

static void __exit fini(void)
{
    ipt_unregister_target(&ipt_account_reg);

    kfree(ipt_account_tables);
    ipt_account_tables = NULL;
        
    kfree(ipt_account_handles);
    ipt_account_handles = NULL;
}

module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
