#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

#define TIMEOUT 10

static char *ping_argv[8];

static int execute_ping()
{
	pid_t ping_pid;
	int status;

	ping_pid = fork();
	if (ping_pid == 0) {
		fclose(stdout);
		fclose(stdin);
		// Must include some PATH for busybox on OpenWRT
		char *envp[] = { "PATH=/bin:/sbin:/usr/bin:/usr/sbin", NULL };
		execve("/bin/ping", ping_argv, envp);

		perror("ping process execve failed [%m]");
		return EXIT_FAILURE;
	}

	waitpid(ping_pid, &status, 0);

	return WEXITSTATUS(status);
}

void wait_for_online()
{
	static time_t last_time = -1;
	time_t current_time = time(NULL);
	int recent = current_time != -1 &&
		     difftime(current_time, last_time) < 60;
	if (!recent) {
		int ping_ret = -1;
		for (int ping_count = 0;
		     ping_count < TIMEOUT && ping_ret != 0;
		     ping_count++) {
			ping_ret = execute_ping();
		}
	}

	last_time = current_time;
}

void generate_ping_argv(const char *ip_address, const char *ifname)
{
	const char *ping_arguments[] = {
		"/bin/ping", "-c", "1", "-W", "1", "-I", ifname, ip_address
	};
	const int argument_count =
		sizeof(ping_arguments) / sizeof(ping_arguments[0]);
	ping_argv = calloc(argument_count + 1, sizeof(char *));
	if (!ping_argv) {
		perror("malloc() ping arguments");
		exit(EXIT_FAILURE);
	}

	for (int array_index = 0; array_index < argument_count; array_index++) {
		char *str_cpy = strdup(ping_arguments[array_index]);
		if (str_cpy) {
			ping_argv[array_index] = str_cpy;
		} else {
			perror("malloc() ping argument");
			exit(EXIT_FAILURE);
		}
	}
}