#ifndef _ipt_ACCOUNT_cl_H
#define _ipt_ACCOUNT_cl_H

// TODO: Path needs fixing
#include "../ipt_ACCOUNT.h"

// TODO: Move these to the ip_tables.h
#define IPT_BASE_CTL		64	/* base for firewall socket options */
#define IPT_SO_SET_ACCOUNT_HANDLE_FREE	(IPT_BASE_CTL + 3)
#define IPT_SO_SET_ACCOUNT_MAX		IPT_SO_SET_ACCOUNT_HANDLE_FREE

#define IPT_SO_GET_ACCOUNT_PREPARE_READ (IPT_BASE_CTL + 3)
#define IPT_SO_GET_ACCOUNT_PREPARE_READ_FLUSH (IPT_BASE_CTL + 4)
#define IPT_SO_GET_ACCOUNT_GET_DATA (IPT_BASE_CTL + 5)
#define IPT_SO_GET_ACCOUNT_MAX      IPT_SO_GET_ACCOUNT_GET_DATA

#define IPT_ACCOUNT_MIN_BUFSIZE 4096    /* Don't set this below the size of struct ipt_account_handle_sockopt */

struct ipt_ACCOUNT_context
{
    int sockfd;
    struct ipt_account_handle_sockopt handle;
    
    unsigned int data_size;
    void *data;
    unsigned int pos;
        
    char *error_str;
};

int ipt_ACCOUNT_init(struct ipt_ACCOUNT_context *ctx);
void ipt_ACCOUNT_deinit(struct ipt_ACCOUNT_context *ctx);

int ipt_ACCOUNT_read_entries(struct ipt_ACCOUNT_context *ctx, char *table, char dont_flush);
struct ipt_account_handle_ip *ipt_ACCOUNT_get_next_entry(struct ipt_ACCOUNT_context *ctx);
/* ipt_ACCOUNT_free_entries is for internal use only function as this library
   is constructed to be used in a loop -> Don't allocate memory all the time.
   The data buffer is freed on deinit() */

#endif
