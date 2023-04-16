#include <time.h>
#include <string.h>

#include "ping.h"

#define TIMEOUT 60

void hold_for_online()
{
	static time_t last_time = -1;
	time_t current_time = time(NULL);
	int recent =
		current_time != -1 && difftime(current_time, last_time) < 60;
	if (!recent) {
		int ping_ret = 0;
		for (int ping_count = 0; ping_count < TIMEOUT && ! ping_ret;
		     ping_count++) {
			ping_ret = send_ping();
		}
	}

	last_time = current_time;
}

void setup_hold(const char *hostname)
{
	setup_ping(hostname);
}

void cleanup_hold()
{
	cleanup_ping();
}