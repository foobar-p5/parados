/*  parados
		the simple home media server
	
	this software is licensed under ISC
	check LICENCE for more details
*/

#include <errno.h>
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

void die(const char* s, int e);
void run(void);
void setup(void);
int write_all(int fd, const void* buf, size_t n);

int sock;

void die(const char* s, int e)
{
	perror(s);
	exit(e);
}

void logmsg(bool verbose, const char* tag, const char* fmt, ...)
{
	if (!verbose)
		return;

	time_t t = time(NULL);
	struct tm tmv;
	char ts[9];

	if (localtime_r(&t, &tmv))
		snprintf(
			ts, sizeof(ts),
			"%02d:%02d:%02d",
			tmv.tm_hour,
			tmv.tm_min,
			tmv.tm_sec
		);
	else
		snprintf(ts, sizeof(ts), "??:??:??");

	fprintf(stderr, "%s [%s] ", ts, tag);

	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fputc('\n', stderr);
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
		logmsg(verbose_log, "CORE", "connection accepted");

		(void)http_handle(c);
		shutdown(c, SHUT_WR);
		close(c);
	}
}

void setup(void)
{
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

	ret = listen(sock, LISTEN_BACKLOG);
	if (ret < 0)
		die("listen", EXIT_FAILURE);

	logmsg(verbose_log, "CORE", "listening on %s:%d", server_addr, server_port);
}

int main(void)
{
	setup();
#ifdef __OpenBSD__
	if (pledge("stdio inet", NULL) < 0)
		die("pledge", EXIT_FAILURE);
#endif
	run();
	return EXIT_SUCCESS;
}

