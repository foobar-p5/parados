#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "http.h"

static int read_reqline(int c, char* method, size_t msz, char* path, size_t psz);
static void reply_text(int c, const char* status, const char* body);
static int write_all(int fd, const void* buf, size_t n);

int http_handle(char c)
{
	char method[16];
	char path[1024];

	if (read_reqline(c, method, sizeof(method), path, sizeof(path)) < 0) {
		reply_text(c, HTTP_400, "bad request\n");
		return -1;
	}

	if (strcmp(method, "GET") != 0) {
		reply_text(c, HTTP_405, "method not allowed\n");
		return 0;
	}

	if (strcmp(path, "/ping") == 0) {
		reply_text(c, HTTP_200, "ok\n");
		return 0;
	}

	reply_text(c, HTTP_404, "not found\n");
	return 0;
}

static int read_reqline(int c, char* method, size_t msz, char* path, size_t psz)
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

static void reply_text(int c, const char* status, const char* body)
{
	char resp[HTTP_RESP_MAX];
	int n = snprintf(
		resp, sizeof(resp),

		"%s"
		HTTP_TEXT
		HTTP_LENGTH
		HTTP_CLOSE
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

static int write_all(int fd, const void* buf, size_t n)
{
	const char* p = buf;

	while (n > 0) {
		size_t w = write(fd, p, n);
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
