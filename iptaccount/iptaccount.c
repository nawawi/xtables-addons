/***************************************************************************
 *   Copyright (C) 2004 by Intra2net AG                                    *
 *   opensource@intra2net.com                                              *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Lesser General Public License           *
 *   version 2.1 as published by the Free Software Foundation;             *
 *                                                                         *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include <ipt_ACCOUNT_cl.h>

char *addr_to_dotted(unsigned int addr)
{
    static char buf[20];
    const unsigned char *bytep;

    bytep = (const unsigned char *) &addr;
    sprintf(buf, "%u.%u.%u.%u", bytep[0], bytep[1], bytep[2], bytep[3]);
    return buf;
}

int main(int argc, char *argv[])
{
    struct ipt_ACCOUNT_context ctx;
    struct ipt_account_handle_ip *entry;
    int i = 0;
    
    if (argc != 2)
    {
        printf("Syntax: %s TABLE-NAME\n", argv[0]);
        exit (-1);
    }
    
    if(ipt_ACCOUNT_init(&ctx))
    {
        printf("Init failed: %s\n", ctx.error_str);
        exit (-1);
    }

    while (1)
    {
        printf("Run #%d\n", i);
        
        // Get entries from table test
        if (ipt_ACCOUNT_read_entries(&ctx, argv[1], 0))
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
	i++;
    }
            
    ipt_ACCOUNT_deinit(&ctx);
    exit (0);
}
