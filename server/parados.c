/*  parados
		the simple home media server

	this software is licensed under ISC
	check LICENCE for more details
*/

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "config.h"
#include "http.h"
#include "log.h"
#include "scan.h"

void die(const char* s, int e);
void run(void);
void setup(void);

int sock;
struct library lib;

void die(const char* s, int e)
{
	perror(s);
	exit(e);
}

void run(void)
{
	for (;;) {
		int c = accept(sock, NULL, NULL);
		if (c < 0) {
			if (errno == EINTR)
				continue;
			continue;
		}
		LOG(verbose_log, "CORE", "Connection accepted");

		pid_t pid = fork();
		if (pid < 0) {
			close(c);
			continue;
		}

		if (pid == 0) {
			(void)http_handle(c);
			shutdown(c, SHUT_WR);
			close(c);
			_exit(EXIT_SUCCESS);
		}

		close(c);
	}
}

void setup(void)
{
	signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE */
	signal(SIGCHLD, SIG_IGN); /* reap children to prevent
								 them to turn into zombies */

	config_load();

	int ret = 1;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		die("socket", EXIT_FAILURE);

	int yes = 1;
	ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	if (ret < 0)
		die("setsockopt", EXIT_FAILURE);

	struct sockaddr_in a;
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_port = htons(server_port);
	ret = inet_pton(AF_INET, server_addr, &a.sin_addr);
	if (ret != 1)
		die("inet_pton", EXIT_FAILURE);

	ret = bind(sock, (struct sockaddr*)&a, sizeof(a));
	if (ret < 0)
		die("bind", EXIT_FAILURE);

	if (scan_library(&lib, media_dir) < 0)
		die("scan_library", EXIT_FAILURE);
	LOG(verbose_log, "SCAN", "Cached %zu items", lib.len);

	ret = listen(sock, LISTEN_BACKLOG);
	if (ret < 0)
		die("listen", EXIT_FAILURE);

	LOG(verbose_log, "CORE", "Listening on %s:%d", server_addr, server_port);
}

int main(void)
{
	setup();
#ifdef __OpenBSD__
	if (pledge("stdio inet", NULL) < 0)
		die("pledge", EXIT_FAILURE);
#endif /* __OpenBSD__ */
	run();
	return EXIT_SUCCESS;
}

