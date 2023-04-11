#ifndef ETHERWAKE_NFQUEUE_PING_H
#define ETHERWAKE_NFQUEUE_PING_H

void wait_for_online();
void generate_ping_argv(const char *ip_address, const char *ifname);

#endif //ETHERWAKE_NFQUEUE_PING_H
