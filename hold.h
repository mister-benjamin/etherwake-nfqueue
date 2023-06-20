#ifndef ETHERWAKE_NFQUEUE_HOLD_H
#define ETHERWAKE_NFQUEUE_HOLD_H

void hold_for_online();
int setup_hold(const char *hostname);
void cleanup_hold();

#endif //ETHERWAKE_NFQUEUE_HOLD_H
