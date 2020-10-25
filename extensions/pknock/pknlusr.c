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

static struct sockaddr_nl local_addr;
static int sock_fd;

static unsigned char *buf;

static struct xt_pknock_nl_msg *nlmsg;

int main(void)
{
	int status;
	int group = GROUP;

	int buf_size;

	const char *ip;
	char ipbuf[48];

	sock_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);

	if (sock_fd == -1) {
		perror("socket()");
		return 1;
	}

	memset(&local_addr, 0, sizeof(local_addr));
	local_addr.nl_family = AF_NETLINK;
	local_addr.nl_pid = getpid();
	local_addr.nl_groups = group;
	status = bind(sock_fd, (struct sockaddr *)&local_addr, sizeof(local_addr));
	if (status == -1) {
		close(sock_fd);
		perror("bind()");
		return 1;
	}

	buf_size = sizeof(struct xt_pknock_nl_msg) + sizeof(struct cn_msg) + sizeof(struct nlmsghdr);
	buf = malloc(buf_size);

	if (!buf) {
		perror("malloc()");
		return 1;
	}

	while(1) {

		memset(buf, 0, buf_size);
		status = recv(sock_fd, buf, buf_size, 0);
		if (status <= 0) {
			perror("recv()");
			return 1;
		}
		nlmsg = (struct xt_pknock_nl_msg *)(buf + sizeof(struct cn_msg) + sizeof(struct nlmsghdr));
		ip = inet_ntop(AF_INET, &nlmsg->peer_ip, ipbuf, sizeof(ipbuf));
		printf("rule_name: %s - ip %s\n", nlmsg->rule_name, ip);

	}

	close(sock_fd);

	free(buf);

	return 0;
}
