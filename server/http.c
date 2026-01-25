#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "http.h"
#include "json.h"
#include "log.h"
#include "scan.h"

static int read_reqline(int c, char* method, size_t msz, char* path, size_t psz);
static void reply_json(int c, const char* status, const char* body, size_t len);
static void reply_text(int c, const char* status, const char* body);
static int write_all(int fd, const void* buf, size_t n);

int http_handle(int c)
{
	char method[16];
	char path[1024];

	if (read_reqline(c, method, sizeof(method), path, sizeof(path)) < 0) {
		reply_text(c, HTTP_400, "bad request\n");
		return -1;
	}
	LOG(verbose_log, "HTTP", "request: %s %s", method, path);

	if (strcmp(method, "GET") != 0) {
		LOG(verbose_log, "HTTP", "method not allowed: %s", method);
		reply_text(c, HTTP_405, "method not allowed\n");
		return 0;
	}

	if (strcmp(path, "/ping") == 0) {
		LOG(verbose_log, "HTTP", "route /ping");
		reply_text(c, HTTP_200, "ok\n");
		return 0;
	}

	if (strcmp(path, "/library") == 0) {
		LOG(verbose_log, "HTTP", "route /library");
		struct library l;
		struct json j;

		if (scan_library(&l, media_dir) < 0) {
			LOG(verbose_log, "SCAN", "scan failed");
			reply_text(c, HTTP_500, "scan failed\n");
			return -1;
		}
		LOG(verbose_log, "SCAN", "found %zu items", l.len);

		if (json_library(&j, &l) < 0) {
			LOG(verbose_log, "JSON", "encode failed");
			scan_library_free(&l);
			reply_text(c, HTTP_500, "json failed\n");
			return -1;
		}
		LOG(verbose_log, "JSON", "encoded %zu bytes", j.len);

		scan_library_free(&l);
		reply_json(c, HTTP_200, j.buf, j.len);
		json_free(&j);

		return 0;
	}

	LOG(verbose_log, "HTTP", "route not found: %s", path);
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
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (r == 0)
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

static void reply_json(int c, const char* status, const char* body, size_t len)
{
	char resp[HTTP_RESP_MAX];
	int n = snprintf(
		resp, sizeof(resp),

		"%s"
		HTTP_JSON
		HTTP_LENGTH
		HTTP_CLOSE
		"\r\n",

		status, len
	);

	if (n < 0)
		return;

	if ((size_t)n >= sizeof(resp))
		n = (int)(sizeof(resp) - 1);

	(void)write_all(c, resp, (size_t)n);
	(void)write_all(c, body, len);
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

