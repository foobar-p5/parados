#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "config.h"

void die(const char* s, int e);
int read_reqline(int c, char* method, size_t msz, char* path, size_t psz);
void reply_text(int c, const char* status, const char* body);
void run(void);
void setup(void);
int write_all(int fd, const void* buf, size_t n);

int sock;

void die(const char* s, int e)
{
	perror(s);
	exit(e);
}

int read_reqline(int c, char* method, size_t msz, char* path, size_t psz)
{
	char buf[HTTP_REQ_MAX];
	size_t used = 0;

	for (;;) {
		if (used + 1 >= sizeof(buf))
			return -1;

		ssize_t r = read(c, buf + used, sizeof(buf) - 1 - used);
		if (r <= 0)
			return -1;

		used += (size_t)r;
		buf[used] = '\0';

		char* eol = strstr(buf, "\r\n");
		if (eol) {
			*eol = '\0';
			break;
		}
	}

	if (sscanf(buf, "%15s %1023s", method, path) != 2)
		return -1;

	method[msz-1] = '\0';
	path[psz-1] = '\0';

	return 0;
}

void reply_text(int c, const char* status, const char* body)
{
	char resp[HTTP_RESP_MAX];
	int n = snprintf(
		resp, sizeof(resp),

		"%s"
		"Content-Type: text/plain\r\n"
		"Content-Length: %zu\r\n"
		"Connection: close\r\n"
		"\r\n"
		"%s",

		status,
		strlen(body), body
	);

	if (n < 0)
		return;

	if ((size_t)n >= sizeof(resp))
		n = (int)(sizeof(resp) - 1);

	(void)write_all(c, resp, (size_t)n);
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

		char method[16];
		char path[1024];

		if (read_reqline(c, method, sizeof(method), path, sizeof(path)) < 0) {
			reply_text(c, "HTTP/1.1 400 Bad Request\r\n", "bad request\n");
			shutdown(c, SHUT_WR);
			close(c);
			continue;
		}

		if (strcmp(method, "GET") != 0) {
			reply_text(c, "HTTP/1.1 405 Method Not Allowed\r\n", "method not allowed\n");
			shutdown(c, SHUT_WR);
			close(c);
			continue;
		}

		if (strcmp(path, "/ping") == 0) {
			reply_text(c, "HTTP/1.1 200 OK\r\n", "ok\n");
			shutdown(c, SHUT_WR);
			close(c);
			continue;
		}

		reply_text(c, "HTTP/1.1 404 Not Found\r\n", "not found\n");
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

	if (verbose_log)
		printf("listening on %s:%d\n", server_addr, server_port);
}

int write_all(int fd, const void* buf, size_t n)
{
	const char* p = buf;

	while (n > 0) {
		ssize_t w = write(fd, p, n);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		p += (size_t)w;
		n -= (size_t)w;
	}

	return 0;
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

