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

/* Recursive free of all data structures */
void ipt_account_data_free(void *data, unsigned char depth)
{
    // Empty data set
    if (!data)
        return;
        
    // Free for 8 bit network
    if (depth == 0)
    {
        free_page((unsigned long)data);
        data = NULL;
        return;
    }
    
    // Free for 16 bit network
    if (depth == 1)
    {
        struct ipt_account_mask_16 *mask_16 = (struct ipt_account_mask_16 *)data;
        unsigned char b;
        for (b=0; b < 255; b++)
        {
            if (mask_16->mask_24[b] != 0)
            {
                free_page((unsigned long)mask_16->mask_24[b]);
                mask_16->mask_24[b] = NULL;
            }
        }
        free_page((unsigned long)data);
        data = NULL;
        return;
    } 
   
    // Free for 24 bit network
    if (depth == 3)
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
                        free_page((unsigned long)mask_16->mask_24[b]);
                        mask_16->mask_24[b] = NULL;
                    }
                }
                free_page((unsigned long)mask_16);
                mask_16 = NULL;
            }
        }
        free_page((unsigned long)data);
        data = NULL;
        return;
    }
    
    printk("ACCOUNT: ipt_account_data_free called with unknown depth: %d\n", depth);
    return;
}

/* Look for existing table / insert new one. Return internal ID or -1 on error */
int ipt_account_table_insert(char *name, unsigned int ip, unsigned int netmask)
{
    unsigned int i;

    DEBUGP("ACCOUNT: ipt_account_table_insert: %s, %u.%u.%u.%u/%u.%u.%u.%u\n", name, NIPQUAD(ip), NIPQUAD(netmask));

    // Look for existing table
    for (i = 0; i < ACCOUNT_MAX_TABLES; i++)
    {
        if (strcmp(ipt_account_tables[i].name, name) == 0)
        {
            DEBUGP("ACCOUNT: Found existing slot: %d - %u.%u.%u.%u/%u.%u.%u.%u\n", i,
                   NIPQUAD(ipt_account_tables[i].ip), NIPQUAD(ipt_account_tables[i].netmask));
            
            if (ipt_account_tables[i].ip != ip || ipt_account_tables[i].netmask != netmask)
            {
                printk("ACCOUNT: Table %s found, but IP/netmask mismatch. IP/netmask found: %u.%u.%u.%u/%u.%u.%u.%u\n",
                        name, NIPQUAD(ipt_account_tables[i].ip), NIPQUAD(ipt_account_tables[i].netmask));
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
            
            // Calculate netsize
            unsigned int j, calc_mask, netsize=0;
            calc_mask = htonl(netmask);
            for (j = 31; j > 0; j--)
            {
                if (calc_mask&(1<<j))
                    netsize++;
                else
                    break;
            }
            
            // Calculate depth from netsize
            if (netsize >= 24)
                ipt_account_tables[i].depth = 0;
            else if (netsize >= 16)
                ipt_account_tables[i].depth = 1;
            else if(netsize >= 8)
                ipt_account_tables[i].depth = 2;
            
            printk("ACCOUNT: calculated netsize: %u -> ipt_account_table depth %u\n", netsize, ipt_account_tables[i].depth);
                        
            ipt_account_tables[i].refcount++;
            if (!(ipt_account_tables[i].data = (void *)get_zeroed_page(GFP_KERNEL)))
            {
                printk("ACCOUNT: out of memory for data of table: %s\n", name);
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

    spin_lock_bh(&ipt_account_lock);
    int table_nr = ipt_account_table_insert(info->table_name, info->net_ip, info->net_mask);
    if (table_nr == -1)
    {
        printk("ACCOUNT: Table insert problem. Aborting\n");
        spin_unlock_bh(&ipt_account_lock);
        return 0;
    }
    // Table nr caching so we don't have to do an extra string compare for every packet
    info->table_nr = table_nr;
    
    spin_unlock_bh(&ipt_account_lock);

    return 1;
}

void ipt_account_deleteentry(void *targinfo, unsigned int targinfosize)
{
    unsigned int i;
    struct ipt_account_info *info = targinfo;
    
    if (targinfosize != IPT_ALIGN(sizeof(struct ipt_account_info))) {
        DEBUGP("ACCOUNT: targinfosize %u != %u\n",
                targinfosize, IPT_ALIGN(sizeof(struct ipt_account_info)));
    }

    spin_lock_bh(&ipt_account_lock);
    
    DEBUGP("ACCOUNT: ipt_account_deleteentry called for table: %s (#%d)\n", info->table_name, info->table_nr);
    
    info->table_nr = -1;    // Set back to original state
    
    // Look for table
    for (i = 0; i < ACCOUNT_MAX_TABLES; i++)
    {
        if (strcmp(ipt_account_tables[i].name, info->table_name) == 0)
        {
            DEBUGP("ACCOUNT: Found table at slot: %d\n", i);
            
            ipt_account_tables[i].refcount--;
            DEBUGP("ACCOUNT: Refcount left: %d\n", ipt_account_tables[i].refcount);

            // Table not needed anymore?
            if (ipt_account_tables[i].refcount == 0)
            {
                DEBUGP("ACCOUNT: Destroying table at slot: %d\n", i);
                ipt_account_data_free(ipt_account_tables[i].data, ipt_account_tables[i].depth);
                memset(&ipt_account_tables[i], 0, sizeof(struct ipt_account_table));
            }
            
            spin_unlock_bh(&ipt_account_lock);
            return;
        }
    }

    // Table not found
    printk("ACCOUNT: Table %s not found for destroy\n", info->table_name);
    spin_unlock_bh(&ipt_account_lock);
}

void ipt_account_depth0_insert(struct ipt_account_mask_24 *mask_24, unsigned int net_ip, unsigned int netmask,
                               unsigned int src_ip, unsigned int dst_ip, unsigned int size, unsigned int *itemcount)
{
    unsigned char is_src = 0, is_dst = 0;
    
    DEBUGP("ACCOUNT: ipt_account_depth0_insert: %u.%u.%u.%u/%u.%u.%u.%u for net %u.%u.%u.%u/%u.%u.%u.%u, size: %u\n",
            NIPQUAD(src_ip), NIPQUAD(dst_ip), NIPQUAD(net_ip), NIPQUAD(netmask), size);
        
    // Check if src/dst is inside our network.
    // Special: net_ip = 0.0.0.0/0 gets stored as src in slot 0
    if (!netmask)
        src_ip = 0;
    if ((net_ip&netmask) == (src_ip&netmask))
        is_src = 1;
    if ((net_ip&netmask) == (dst_ip&netmask) && netmask)
        is_dst = 1;
    
    if (!is_src && !is_dst)
    {
        DEBUGP("ACCOUNT: Skipping packet %u.%u.%u.%u/%u.%u.%u.%u for net %u.%u.%u.%u/%u.%u.%u.%u\n",
                NIPQUAD(src_ip), NIPQUAD(dst_ip), NIPQUAD(net_ip), NIPQUAD(netmask));
        return;
    }
        
    // Check if this entry is new
    char is_new_ip = 0;
    
    // Increase size counters
    if (is_src)
    {
        // Calculate network slot
        unsigned char slot = (unsigned char)((src_ip&0xFF000000) >> 24);
        DEBUGP("ACCOUNT: Calculated SRC 8 bit network slot: %d\n", slot);
        if (!mask_24->ip[slot].src_packets && !mask_24->ip[slot].dst_packets)
            is_new_ip = 1;
        
        mask_24->ip[slot].src_packets++;
        mask_24->ip[slot].src_bytes+=size;
    }
    if (is_dst)
    {
        unsigned char slot = (unsigned char)((dst_ip&0xFF000000) >> 24);
        DEBUGP("ACCOUNT: Calculated DST 8 bit network slot: %d\n", slot);
        if (!mask_24->ip[slot].src_packets && !mask_24->ip[slot].dst_packets)
            is_new_ip = 1;
        
        mask_24->ip[slot].dst_packets++;
        mask_24->ip[slot].dst_bytes+=size;
    }
    
    if (is_new_ip)
        (*itemcount)++;
}

void ipt_account_depth1_insert(struct ipt_account_mask_16 *mask_16, unsigned int net_ip, unsigned int netmask,
                               unsigned int src_ip, unsigned int dst_ip, unsigned int size, unsigned int *itemcount)
{
    // Do we need to process src IP?
    if ((net_ip&netmask) == (src_ip&netmask))
    {
        unsigned char slot = (unsigned char)((src_ip&0x00FF0000) >> 16);
        DEBUGP("ACCOUNT: Calculated SRC 16 bit network slot: %d\n", slot);
        
        // Do we need to create a new mask_24 bucket?
        if (!mask_16->mask_24[slot] && !(mask_16->mask_24[slot] = (void *)get_zeroed_page(GFP_KERNEL)))
        {
            printk("ACCOUNT: Can't process packet because out of memory!\n");
            return;
        }
        
        ipt_account_depth0_insert((struct ipt_account_mask_24 *)mask_16->mask_24[slot], net_ip, netmask,
                                    src_ip, dst_ip, size, itemcount);
    }
    
    // Do we need to process dst IP?
    if ((net_ip&netmask) == (dst_ip&netmask))
    {
        unsigned char slot = (unsigned char)((dst_ip&0x00FF0000) >> 16);
        DEBUGP("ACCOUNT: Calculated DST 16 bit network slot: %d\n", slot);
        
        // Do we need to create a new mask_24 bucket?
        if (!mask_16->mask_24[slot] && !(mask_16->mask_24[slot] = (void *)get_zeroed_page(GFP_KERNEL)))
        {
            printk("ACCOUT: Can't process packet because out of memory!\n");
            return;
        }
        
        ipt_account_depth0_insert((struct ipt_account_mask_24 *)mask_16->mask_24[slot], net_ip, netmask,
                                    src_ip, dst_ip, size, itemcount);
    }
}

void ipt_account_depth2_insert(struct ipt_account_mask_8 *mask_8, unsigned int net_ip, unsigned int netmask,
                               unsigned int src_ip, unsigned int dst_ip, unsigned int size, unsigned int *itemcount)
{
    // Do we need to process src IP?
    if ((net_ip&netmask) == (src_ip&netmask))
    {
        unsigned char slot = (unsigned char)((src_ip&0x0000FF00) >> 8);
        DEBUGP("ACCOUNT: Calculated SRC 24 bit network slot: %d\n", slot);
                
        // Do we need to create a new mask_24 bucket?
        if (!mask_8->mask_16[slot] && !(mask_8->mask_16[slot] = (void *)get_zeroed_page(GFP_KERNEL)))
        {
            printk("ACCOUNT: Can't process packet because out of memory!\n");
            return;
        }
        
        ipt_account_depth1_insert((struct ipt_account_mask_16 *)mask_8->mask_16[slot], net_ip, netmask,
                                    src_ip, dst_ip, size, itemcount);
    }
    
    // Do we need to process dst IP?
    if ((net_ip&netmask) == (dst_ip&netmask))
    {
        unsigned char slot = (unsigned char)((dst_ip&0x0000FF00) >> 8);
        DEBUGP("ACCOUNT: Calculated DST 24 bit network slot: %d\n", slot);
        
        // Do we need to create a new mask_24 bucket?
        if (!mask_8->mask_16[slot] && !(mask_8->mask_16[slot] = (void *)get_zeroed_page(GFP_KERNEL)))
        {
            printk("ACCOUNT: Can't process packet because out of memory!\n");
            return;
        }
        
        ipt_account_depth1_insert((struct ipt_account_mask_16 *)mask_8->mask_16[slot], net_ip, netmask,
                                    src_ip, dst_ip, size, itemcount);
    }
}

static unsigned int ipt_account_target(struct sk_buff **pskb,
    unsigned int hooknum,
    const struct net_device *in,
    const struct net_device *out,
    const void *targinfo,
    void *userinfo)
{
    const struct ipt_account_info *info = (const struct ipt_account_info *)targinfo;
    unsigned int src_ip = (*pskb)->nh.iph->saddr;
    unsigned int dst_ip = (*pskb)->nh.iph->daddr;
    unsigned int size = ntohs((*pskb)->nh.iph->tot_len);
    
    spin_lock_bh(&ipt_account_lock);
    
    if (ipt_account_tables[info->table_nr].name[0] == 0)
    {
        printk("ACCOUNT: ipt_account_target: Invalid table id %u. IPs %u.%u.%u.%u/%u.%u.%u.%u\n",
               info->table_nr, NIPQUAD(src_ip), NIPQUAD(dst_ip));
        spin_unlock_bh(&ipt_account_lock);
        return IPT_CONTINUE;
    }
    
    // 8 bit network or "any" network
    if (ipt_account_tables[info->table_nr].depth == 0)
    {
        // Count packet and check if the IP is new
        ipt_account_depth0_insert((struct ipt_account_mask_24 *)ipt_account_tables[info->table_nr].data,
                                  ipt_account_tables[info->table_nr].ip, ipt_account_tables[info->table_nr].netmask,
                                  src_ip, dst_ip, size, &ipt_account_tables[info->table_nr].itemcount);
        spin_unlock_bh(&ipt_account_lock);
        return IPT_CONTINUE;
    }    
    
    // 16 bit network
    if (ipt_account_tables[info->table_nr].depth == 1)
    {
        ipt_account_depth1_insert((struct ipt_account_mask_16 *)ipt_account_tables[info->table_nr].data,
                                  ipt_account_tables[info->table_nr].ip, ipt_account_tables[info->table_nr].netmask,
                                  src_ip, dst_ip, size, &ipt_account_tables[info->table_nr].itemcount);
        spin_unlock_bh(&ipt_account_lock);
        return IPT_CONTINUE;
    }
    
    // 24 bit network
    if (ipt_account_tables[info->table_nr].depth == 2)
    {
        ipt_account_depth2_insert((struct ipt_account_mask_8 *)ipt_account_tables[info->table_nr].data,
                                  ipt_account_tables[info->table_nr].ip, ipt_account_tables[info->table_nr].netmask,
                                  src_ip, dst_ip, size, &ipt_account_tables[info->table_nr].itemcount);
        spin_unlock_bh(&ipt_account_lock);
        return IPT_CONTINUE;
    }
    
    printk("ACCOUNT: ipt_account_target: Unable to process packet. Table id %u. IPs %u.%u.%u.%u/%u.%u.%u.%u\n",
            info->table_nr, NIPQUAD(src_ip), NIPQUAD(dst_ip));
    
    spin_unlock_bh(&ipt_account_lock);
    return IPT_CONTINUE;
}

static struct ipt_target ipt_account_reg
= { { NULL, NULL }, "ACCOUNT", ipt_account_target, ipt_account_checkentry, ipt_account_deleteentry, 
    THIS_MODULE };

static int __init init(void)
{
    if (!(ipt_account_tables = kmalloc(ACCOUNT_MAX_TABLES*sizeof(struct ipt_account_table), GFP_KERNEL)))
    {
            printk("ACCOUNT: Out of memory allocating account_tables structure");
            return -EINVAL;
    }
    memset(ipt_account_tables, 0, ACCOUNT_MAX_TABLES*sizeof(struct ipt_account_table));
                            
    if (!(ipt_account_handles = kmalloc(ACCOUNT_MAX_HANDLES*sizeof(struct ipt_account_handle), GFP_KERNEL)))
    {
            printk("ACCOUNT: Out of memory allocating account_handles structure");
            kfree (ipt_account_tables);
            ipt_account_tables = NULL;
            return -EINVAL;
    }
    memset(ipt_account_handles, 0, ACCOUNT_MAX_HANDLES*sizeof(struct ipt_account_handle));
    
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
