#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <ipt_ACCOUNT_cl.h>

int ipt_ACCOUNT_init(struct ipt_ACCOUNT_context *ctx)
{
    memset (ctx, 0, sizeof(struct ipt_ACCOUNT_context));
    
    ctx->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (ctx->sockfd < 0)
    {
        ctx->sockfd = -1;
        ctx->error_str = "Can't open socket to kernel. Permission denied or ipt_ACCOUNT module not loaded";
        return -1;
    }
    
    // 4096 bytes default buffer should save us from reallocations
    // as it fits 200 concurrent active clients
    if((ctx->data = (void *)malloc(IPT_ACCOUNT_MIN_BUFSIZE)) == NULL)
    {
        close (ctx->sockfd);
        ctx->sockfd = -1;
        ctx->error_str = "Out of memory for data buffer";
        return -1;
    }
    ctx->data_size = IPT_ACCOUNT_MIN_BUFSIZE;
    
    return 0;
}

void ipt_ACCOUNT_free_entries(struct ipt_ACCOUNT_context *ctx)
{
    if (ctx->handle.handle_nr >= 0)
    {
        setsockopt(ctx->sockfd, IPPROTO_IP, IPT_SO_SET_ACCOUNT_HANDLE_FREE, &ctx->handle, sizeof (struct ipt_account_handle_sockopt));
        ctx->handle.handle_nr = -1;
    }

    ctx->handle.itemcount = 0;
    ctx->pos = 0;
}

void ipt_ACCOUNT_deinit(struct ipt_ACCOUNT_context *ctx)
{
    free(ctx->data);
    ctx->data = NULL;

    ipt_ACCOUNT_free_entries(ctx);
        
    close(ctx->sockfd);
    ctx->sockfd =-1;
}

int ipt_ACCOUNT_read_entries(struct ipt_ACCOUNT_context *ctx, char *table, char dont_flush)
{
    unsigned int s = sizeof (struct ipt_account_handle_sockopt);
    int rtn;
    
    strncpy(ctx->handle.name, table, ACCOUNT_TABLE_NAME_LEN-1);
    
    // Get table information
    if (!dont_flush)
        rtn = getsockopt(ctx->sockfd, IPPROTO_IP, IPT_SO_GET_ACCOUNT_PREPARE_READ_FLUSH, &ctx->handle, &s);
    else
        rtn = getsockopt(ctx->sockfd, IPPROTO_IP, IPT_SO_GET_ACCOUNT_PREPARE_READ, &ctx->handle, &s);
    
    if (rtn < 0)
    {
        ctx->error_str = "Can't get table information from kernel. Is the table existing?";
        return -1;
    }
    
    // Check data buffer size
    ctx->pos = 0;
    unsigned int new_size = ctx->handle.itemcount * sizeof(struct ipt_account_handle_ip);
    // We want to prevent reallocations all the time
    if (new_size < IPT_ACCOUNT_MIN_BUFSIZE)
        new_size = IPT_ACCOUNT_MIN_BUFSIZE;
    
    // Reallocate if it's too small or twice as big
    if (ctx->data_size < new_size || ctx->data_size > new_size*2)
    {
        // Free old buffer
        free (ctx->data);
        ctx->data_size = 0;
        
        if ((ctx->data = (void*)malloc(new_size)) == NULL)
        {
            ctx->error_str = "Out of memory for data buffer";
            ipt_ACCOUNT_free_entries(ctx);
            return -1;
        }
        
        ctx->data_size = new_size;
    }
    
    // Copy data from kernel
    memcpy(ctx->data, &ctx->handle, sizeof(struct ipt_account_handle_sockopt));
    rtn = getsockopt(ctx->sockfd, IPPROTO_IP, IPT_SO_GET_ACCOUNT_GET_DATA, ctx->data, &ctx->data_size);
    if (rtn < 0)
    {
        ctx->error_str = "Can't get data from kernel. Check /var/log/messages for details.";
        ipt_ACCOUNT_free_entries(ctx);
        return -1;
    }

    // Free kernel handle but don't reset pos/itemcount
    setsockopt(ctx->sockfd, IPPROTO_IP, IPT_SO_SET_ACCOUNT_HANDLE_FREE, &ctx->handle, sizeof (struct ipt_account_handle_sockopt));
    ctx->handle.handle_nr = -1;
    
    return 0;
}

struct ipt_account_handle_ip *ipt_ACCOUNT_get_next_entry(struct ipt_ACCOUNT_context *ctx)
{
    struct ipt_account_handle_ip *rtn;
    
    // Empty or no more items left to return?
    if (!ctx->handle.itemcount || ctx->pos >= ctx->handle.itemcount)
        return NULL;
    
    // Get next entry
    rtn = (struct ipt_account_handle_ip *)(ctx->data + ctx->pos*sizeof(struct ipt_account_handle_ip));
    ctx->pos++;
            
    return rtn;
}

char *addr_to_dotted(unsigned int addr)
{
    static char buf[20];
    const unsigned char *bytep;

    bytep = (const unsigned char *) &addr;
    sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
    return buf;
}

int main(void)
{
    struct ipt_ACCOUNT_context ctx;
    struct ipt_account_handle_ip *entry;
    int i;
    
    if(ipt_ACCOUNT_init(&ctx))
    {
        printf("Init failed: %s\n", ctx.error_str);
        exit (-1);
    }

    for (i = 0; i < 3; i++)
    {
        printf("Run #%d\n", i);
        
        // Get entries from table test
        if (ipt_ACCOUNT_read_entries(&ctx, "test", 0))
        {
            printf("Read failed: %s\n", ctx.error_str);
            ipt_ACCOUNT_deinit(&ctx);
            exit (-1);
        }
        
        // Output and free entries
        while ((entry = ipt_ACCOUNT_get_next_entry(&ctx)) != NULL)
        {
            printf("IP: %s SRC packets: %u bytes: %u DST packets: %u bytes: %u\n",
                   addr_to_dotted(entry->ip), entry->src_packets, entry->src_bytes, entry->dst_packets, entry->dst_bytes);
        }
        sleep(1);
    }
            
    ipt_ACCOUNT_deinit(&ctx);
    exit (0);
}
