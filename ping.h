#ifndef ETHERWAKE_NFQUEUE_PING_H
#define ETHERWAKE_NFQUEUE_PING_H

int setup_ping(const char *hostname);
int send_ping();
int cleanup_ping();

#endif //ETHERWAKE_NFQUEUE_PING_H
