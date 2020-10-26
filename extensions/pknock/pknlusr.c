#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>

#include "xt_pknock.h"

#define DEFAULT_GROUP_ID 1
#define MIN_GROUP_ID DEFAULT_GROUP_ID
#define MAX_GROUP_ID \
	(sizeof((struct sockaddr_nl){0}.nl_groups) * CHAR_BIT)

int main(int argc, char **argv)
{
	int status;
	unsigned int group_id = DEFAULT_GROUP_ID;
	struct sockaddr_nl local_addr = {.nl_family = AF_NETLINK};
	int sock_fd;
	size_t nlmsg_size;
	struct nlmgrhdr *nlmsg;
	struct cn_msg *cn_msg;
	struct xt_pknock_nl_msg *pknock_msg;

	if (argc > 2) {
		char *prog = strdup(argv[0]);
		if (prog == NULL) {
			perror("strdup()");
		} else {
			fprintf(stderr, "%s [ group-id ]\n", basename(prog));
			free(prog);
		}
		exit(EXIT_FAILURE);
	}

	if (argc == 2) {
		long n;
		char *end;

		errno = 0;
		n = strtol(argv[1], &end, 10);
		if (*end || (errno && (n == LONG_MIN || n == LONG_MAX)) ||
		    n < MIN_GROUP_ID || n > MAX_GROUP_ID) {
			fputs("Group ID invalid.\n", stderr);
			exit(EXIT_FAILURE);
		}
		group_id = n;
	}

	sock_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if (sock_fd == -1) {
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	local_addr.nl_groups = 1U << (group_id - 1);
	status = bind(sock_fd, (struct sockaddr *)&local_addr, sizeof(local_addr));
	if (status == -1) {
		perror("bind()");
		goto err_close_sock;
	}

	nlmsg_size = NLMSG_SPACE(sizeof(*cn_msg) + sizeof(*pknock_msg));
	nlmsg = malloc(nlmsg_size);
	if (!nlmsg) {
		perror("malloc()");
		goto err_close_sock;
	}

	while(1) {
		const char *ip;
		char ipbuf[INET_ADDRSTRLEN];

		memset(nlmsg, 0, nlmsg_size);
		status = recv(sock_fd, nlmsg, nlmsg_size, 0);
		if (status < 0) {
			perror("recv()");
			goto err_free_msg;
		}
		if (status == 0)
			break;
		cn_msg = NLMSG_DATA(nlmsg);
		pknock_msg = (struct xt_pknock_nl_msg *)(cn_msg->data);
		ip = inet_ntop(AF_INET, &pknock_msg->peer_ip, ipbuf, sizeof(ipbuf));
		printf("rule_name: %s - ip %s\n", pknock_msg->rule_name, ip);
	}

err_free_msg:
	free(nlmsg);
err_close_sock:
	close(sock_fd);
	exit(status == -1 ? EXIT_FAILURE : EXIT_SUCCESS);
}
