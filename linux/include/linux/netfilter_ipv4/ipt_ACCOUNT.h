#ifndef _IPT_ACCOUNT_H
#define _IPT_ACCOUNT_H

#define ACCOUNT_TABLE_NAME_LEN 32

struct ipt_account_info {
	u_int32_t net_ip;
	u_int32_t net_mask;
	char table_name[ACCOUNT_TABLE_NAME_LEN];
	int32_t table_nr;
};

#endif /*_IPT_ACCOUNT_H*/
