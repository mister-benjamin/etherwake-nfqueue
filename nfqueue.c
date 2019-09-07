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
#include <stdint.h>

#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

#include "nfqueue.h"

extern int debug;

static int recv_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
			 struct nfq_data *nfad, void *data);

int nfqueue_receive(uint16_t queue_num, int (*callback)())
{
	int fd;
	ssize_t len;
	char buf[1024];
	struct nfq_handle *h;
	struct nfq_q_handle *qh;

	h = nfq_open();
	if (!h) {
		fprintf(stderr, "Failed opening nfq\n");
		return 1;
	}

	nfq_unbind_pf(h, AF_INET);
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "Failed to bind nfnetlink\n");
		return 1;
	}

	qh = nfq_create_queue(h, queue_num, recv_callback, callback);
	if (!qh) {
		fprintf(stderr, "Failed to bind socket to queue\n");
		return 1;
	}

	nfq_set_queue_flags(qh, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN);

	if (nfq_set_mode(qh, NFQNL_COPY_META, sizeof(buf)) < 0) {
		fprintf(stderr, "Failed to set copy packet mode\n");
		return 1;
	}

	fd = nfq_fd(h);
	while ((len = recv(fd, buf, sizeof(buf), 0)) >= 0) {
		if (debug)
			printf("Read %zd bytes from NFQUEUE socket\n", len);
		nfq_handle_packet(h, buf, len);
	}

	nfq_destroy_queue(qh);
	nfq_close(h);

	return 0;
}

static int recv_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
			 struct nfq_data *nfad, void *data)
{
	int ret = 0;
	uint32_t id;
	struct nfqnl_msg_packet_hdr *h;
	int (*callback)() = data;

	if (debug)
		printf("Received NFQUEUE callback\n");
	callback();

	h = nfq_get_msg_packet_hdr(nfad);
	if (h) {
		if (debug)
			printf("Issuing verdict\n");
		id = ntohl(h->packet_id);
		ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	return ret;
}
