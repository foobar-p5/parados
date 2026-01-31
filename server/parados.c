/*            parados
	the simple home media server

	See parados(1), parados(7), parados.conf(5)
	for usage information

	This software is licensed under ISC.
	Check LICENCE for more details.
*/

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "config.h"
#include "http.h"
#include "log.h"
#include "scan.h"

#ifndef GIT_VER
#define GIT_VER "unknown"
#endif /* GIT_VER */

static void apply_rlimits(void);
static void* client_thread(void* arg);
static void fd_set_cloexec(int fd);
static void sock_set_timeouts(int fd);

void die(const char* s, int e);
void run(void);
void setup(void);

static sem_t slots;
static int sock;
struct library lib;

static void apply_rlimits(void)
{
	struct rlimit rl;

	rl.rlim_cur = 0;
	rl.rlim_max = 0;
	(void)setrlimit(RLIMIT_CORE, &rl);

	rl.rlim_cur = 1024;
	rl.rlim_max = 1024;
	(void)setrlimit(RLIMIT_NOFILE, &rl);
}

static void* client_thread(void* arg)
{
	int c = (int)(intptr_t)arg;

	sock_set_timeouts(c);
	(void)http_handle(c);
	shutdown(c, SHUT_WR);
	close(c);

	(void)sem_post(&slots);
	return NULL;
}

static void fd_set_cloexec(int fd)
{
	int f = fcntl(fd, F_GETFD);
	if (f >= 0)
		(void)fcntl(fd, F_SETFD, f | FD_CLOEXEC);
}

static void sock_set_timeouts(int fd)
{
	struct timeval tv;
	tv.tv_sec = http_io_timeout;
	tv.tv_usec = 0;

	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

void die(const char* s, int e)
{
	perror(s);
	exit(e);
}

void run(void)
{
	for (;;) {
		int c;

		/* client cap */
		(void)sem_wait(&slots);

		c = accept(sock, NULL, NULL);
		if (c < 0) {
			(void)sem_post(&slots);
			if (errno == EINTR)
				continue;
			continue;
		}

		fd_set_cloexec(c);
		LOG(verbose_log, "CORE", "Connection         Accepted");

		pthread_t t;
		int err = pthread_create(&t, NULL, client_thread, (void*)(intptr_t)c);
		if (err != 0) {
			LOG(true, "CORE", "pthread_create FAILED %d", err);
			close(c);
			(void)sem_post(&slots);
			continue;
		}

		(void)pthread_detach(t);
	}
}

void setup(void)
{
	signal(SIGPIPE, SIG_IGN);

	config_load();
	apply_rlimits();

	if (sem_init(&slots, 0, max_clients) < 0)
		die("sem_init", EXIT_FAILURE);

	int ret = 1;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		die("socket", EXIT_FAILURE);
	fd_set_cloexec(sock);

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
	LOG(verbose_log, "SCAN", "Cached items       %zu", lib.len);

	ret = listen(sock, LISTEN_BACKLOG);
	if (ret < 0)
		die("listen", EXIT_FAILURE);

	LOG(verbose_log, "CORE", "Listening on       %s:%d", server_addr, server_port);
#ifdef __OpenBSD__
	if (unveil(media_dir, "r") < 0)
		die("unveil", EXIT_FAILURE);
	if (unveil(NULL, NULL) < 0)
		die("unveil", EXIT_FAILURE);
#endif
}

int main(int argc, char* argv[])
{
	if (argc > 1) {
		if (strcmp(argv[1], "-v") == 0) {
			printf(
				"parados v%s-%s\n"
				"\n"
				"This software is licensed under ISC.\n"
				"See LICENSE for license information.\n"
				"\n"
				"See parados(1), parados(7), parados.conf(5)\n"
				"for usage information\n",
				VERSION, GIT_VER
			);
			return EXIT_SUCCESS;
		}
		else {
			printf("Invalid command\n");
			printf("See parados(1) for more information\n");
			return EXIT_FAILURE;
		}
	}

	setup();
#ifdef __OpenBSD__
	if (pledge("stdio inet proc rpath", NULL) < 0)
		die("pledge", EXIT_FAILURE);
#endif /* __OpenBSD__ */
	run();
	return EXIT_SUCCESS;
}

