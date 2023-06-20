/*
* Heavily modified version of the busybox ping.c implementation for the etherwake-nfqueue project
*
* Original Copyright Notice:
* Copyright (C) 1999 by Randolph Chung <tausq@debian.org>
*
* Adapted from the ping in netkit-base 0.10:
* Copyright (c) 1989 The Regents of the University of California.
* All rights reserved.
*
* This code is derived from software contributed to Berkeley by
* Mike Muuss.
*
* Licensed under GPLv2 or later
*/

#include <stdio.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>
#include <poll.h>

enum {
	DEFDATALEN = 56,
	MAXIPLEN = 60,
	MAXICMPLEN = 76,
};

int socket_fd = 0;
struct icmp *ping_packet;
struct sockaddr_in receive_addr;
char send_packet[DEFDATALEN + MAXIPLEN + MAXICMPLEN];
char receive_packet[DEFDATALEN + MAXIPLEN + MAXICMPLEN];

int timeout = 0;

int get_dest_addr(const char *hostname)
{
	struct addrinfo hints, *res;
	int ret;

	ret = inet_aton(hostname, &receive_addr.sin_addr);
	if (ret == 0) {
		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_RAW;
		hints.ai_family = AF_INET;

		if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
			fprintf(stderr, "getaddrinfo() failed\n");
			return false;
		}

		memcpy(&receive_addr.sin_addr,
		       &((struct sockaddr_in *)res->ai_addr)->sin_addr,
		       sizeof(struct in_addr));
		freeaddrinfo(res);
	}

	return true;
}

static int create_icmp_socket()
{
	struct protoent *protocol;
	protocol = getprotobyname("icmp");
	if (protocol == NULL) {
		perror("getprotobyname() failed");
		return false;
	}

	socket_fd = socket(AF_INET, SOCK_RAW, protocol->p_proto);
	if (socket_fd < 0) {
		if (errno == EPERM) {
			fprintf(stderr,
				"Failed creating network socket. Are you root?");
		} else {
			perror("socket() failed");
		}
		return false;
	}

	int flags = fcntl(socket_fd, F_GETFL);
	fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK);

	return true;
}

static uint16_t cal_chksum(uint16_t *addr, int nleft)
{
	/*
	 * Our algorithm is simple, using a 32 bit accumulator,
	 * we add sequential 16 bit words to it, and at the end, fold
	 * back all the carry bits from the top 16 bits into the lower
	 * 16 bits.
	 */
	unsigned sum = 0;
	while (nleft > 1) {
		sum += *addr++;
		nleft -= 2;
	}

	/* Mop up an odd byte, if necessary */
	if (nleft == 1) {
		sum += *(uint8_t *)addr;
	}

	/* Add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16); /* add carry */

	return (uint16_t)~sum;
}

static void create_ping_packet(uint16_t process_pid)
{
	ping_packet = (struct icmp *)send_packet;
	ping_packet->icmp_type = ICMP_ECHO;
	ping_packet->icmp_id = process_pid;
	ping_packet->icmp_cksum =
		cal_chksum((uint16_t *)ping_packet, sizeof(send_packet));
}

int setup_ping(const char *hostname)
{
	uint16_t process_pid;

	if (!get_dest_addr(hostname)) {
		fprintf(stderr,
			"Failed getting destination address! Is the address correct?\n");
		return false;
	}

	if (!create_icmp_socket()) {
		fprintf(stderr,
			"Failed creating ICMP socket?\n");
		return false;
	}

	process_pid = htons(getpid());

	create_ping_packet(process_pid);

	return true;
}

void alarm_handler(int signum)
{
	(void)signum;
	timeout = 1;
}

int send_ping()
{
	ssize_t c;
	int received = 0;
	struct icmp *receive_icmp;

	if (sendto(socket_fd, ping_packet, DEFDATALEN + ICMP_MINLEN, 0,
		   (struct sockaddr *)&receive_addr,
		   sizeof(receive_addr)) < 0) {
		perror("sendto()");
	}

	signal(SIGALRM, alarm_handler);
	alarm(1);

	struct pollfd poll_struct;
	poll_struct.fd = socket_fd;
	poll_struct.events = POLLIN;

	while (!timeout && !received) {
		poll(&poll_struct, 1, 1000);
		c = recv(socket_fd, receive_packet, sizeof(receive_packet), 0);

		if (c < 0) {
			if (errno != EINTR && errno != EAGAIN &&
			    errno != EWOULDBLOCK)
				perror("recv()");
			continue;
		}
		if (c >= 76) { /* ip + icmp */
			struct iphdr *iphdr = (struct iphdr *)receive_packet;

			receive_icmp =
				(struct icmp *)(receive_packet +
						(iphdr->ihl
						 << 2)); /* skip ip hdr */
			if (receive_icmp->icmp_id == ping_packet->icmp_id &&
			    receive_icmp->icmp_type == ICMP_ECHOREPLY)
				received = 1;
		}
	}
	return received;
}

void cleanup_ping()
{
	close(socket_fd);
}