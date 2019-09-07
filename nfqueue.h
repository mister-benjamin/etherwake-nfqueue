#ifndef ETHERWAKENFQUEUE_NFQUEUE_H
#define ETHERWAKENFQUEUE_NFQUEUE_H

#include <stdint.h>

int nfqueue_receive(uint16_t queue_num, int (*callback)());

#endif //ETHERWAKENFQUEUE_NFQUEUE_H
