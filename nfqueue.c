/*
 * This file is part of etherwake-nfqueue
 * (https://github.com/mister-benjamin/etherwake-nfqueue)
 *
 * Copyright (C) 2019 Mister Benjamin <144dbspl@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include <linux/netfilter/nfnetlink_queue.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include "nfqueue.h"

#define BUFFER_SIZE (0xFF + MNL_SOCKET_BUFFER_SIZE / 2)

extern int debug;

static int recv_callback(const struct nlmsghdr *nlh, void *data);

static struct mnl_socket *nl;

int nfqueue_receive(uint16_t queue_num, int (*callback)())
{
	uint16_t portid;

	char buf[BUFFER_SIZE];
	struct nlmsghdr *nlh;

	if (debug)
		puts("Setting up netlink socket");

	// Create socket
	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		fprintf(stderr, "mnl_socket_open() failed\n");
		return EXIT_FAILURE;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		fprintf(stderr, "mnl_socket_bind() failed\n");
		return EXIT_FAILURE;
	}

	portid = mnl_socket_get_portid(nl);

	// Configure socket
	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		fprintf(stderr, "Failed binding socket to queue\n");
		return EXIT_FAILURE;
	}

	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_META, 0xFF);
	mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_FAIL_OPEN));
	mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_FAIL_OPEN));
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		fprintf(stderr, "Failed setting queue configuration\n");
		return EXIT_FAILURE;
	}

	/* ENOBUFS is signalled to userspace when packets were lost
	 * on kernel side.  In most cases, userspace isn't interested
	 * in this information, so turn it off.
	 */
	ssize_t ret = 1;
	mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

	if (debug)
		puts("Listening for packages");

	for (;;) {
		ret = mnl_socket_recvfrom(nl, buf, BUFFER_SIZE);
		if (ret == -1) {
			fprintf(stderr, "mnl_socket_recvfrom\n");
			return (EXIT_FAILURE);
		}

		ret = mnl_cb_run(buf, ret, 0, portid, recv_callback, callback);
		if (ret < 0) {
			fprintf(stderr, "mnl_cb_run\n");
			return (EXIT_FAILURE);
		}
	}

	mnl_socket_close(nl);
	return 0;
}

static int nfq_send_verdict(int queue_num, int id)
{
	if (debug)
		printf("Sending verdict for %i in queue %i\n", id, queue_num);

	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
	nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		fprintf(stderr, "Failed sending verdict\n");
		return MNL_CB_ERROR;
	}

	return MNL_CB_OK;
}

static int recv_callback(const struct nlmsghdr *nlh, void *data)
{
	int id, queue_num;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfgenmsg *nfg;
	struct nlattr *attr[NFQA_MAX + 1] = {};
	int (*callback)() = data;

	if (debug)
		puts("Received NFQUEUE callback");
	callback();

	if (nfq_nlmsg_parse(nlh, attr) < 0) {
		fprintf(stderr, "nfq_nlmsg_parse() failed");
		return MNL_CB_ERROR;
	}

	nfg = mnl_nlmsg_get_payload(nlh);

	if (attr[NFQA_PACKET_HDR] == NULL) {
		fprintf(stderr, "metaheader not set\n");
		return MNL_CB_ERROR;
	}

	ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);
	if (!ph) {
		fprintf(stderr, "failed getting payload of metaheader\n");
		return MNL_CB_ERROR;
	}

	id = ntohl(ph->packet_id);
	queue_num = ntohs(nfg->res_id);

	return nfq_send_verdict(queue_num, id);
}