#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/connector.h>

#include "xt_pknock.h"

#define GROUP 1

int main(void)
{
	int status;
	int group = GROUP;
	struct sockaddr_nl local_addr = {.nl_family = AF_NETLINK};
	int sock_fd;
	size_t nlmsg_size;
	struct nlmgrhdr *nlmsg;
	struct cn_msg *cn_msg;
	struct xt_pknock_nl_msg *pknock_msg;

	sock_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);

	if (sock_fd == -1) {
		perror("socket()");
		return 1;
	}

	local_addr.nl_groups = group;
	status = bind(sock_fd, (struct sockaddr *)&local_addr, sizeof(local_addr));
	if (status == -1) {
		close(sock_fd);
		perror("bind()");
		return 1;
	}

	nlmsg_size = NLMSG_SPACE(sizeof(*cn_msg) + sizeof(*pknock_msg));
	nlmsg = malloc(nlmsg_size);
	if (!nlmsg) {
		perror("malloc()");
		return 1;
	}

	while(1) {
		const char *ip;
		char ipbuf[48];

		memset(nlmsg, 0, nlmsg_size);
		status = recv(sock_fd, nlmsg, nlmsg_size, 0);
		if (status <= 0) {
			perror("recv()");
			return 1;
		}
		cn_msg = NLMSG_DATA(nlmsg);
		pknock_msg = (struct xt_pknock_nl_msg *)(cn_msg->data);
		ip = inet_ntop(AF_INET, &pknock_msg->peer_ip, ipbuf, sizeof(ipbuf));
		printf("rule_name: %s - ip %s\n", pknock_msg->rule_name, ip);
	}

	close(sock_fd);
	free(nlmsg);
	return 0;
}
