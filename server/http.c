#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "http.h"
#include "json.h"
#include "log.h"
#include "scan.h"

static const struct item* find_item(uint64_t id);
static int join_path(char* out, size_t outsz, const char* a, const char* b);
static int parse_hex64(const char* s, uint64_t* out);
static int read_reqline(int c, char* method, size_t msz, char* path, size_t psz);
static void reply_json(int c, const char* status, const char* body, size_t len);
static void reply_text(int c, const char* status, const char* body);
static int stream_file(int c, const struct item* it);
static int write_all(int fd, const void* buf, size_t n);


extern struct library lib;

static const struct item* find_item(uint64_t id)
{
	for (size_t i = 0; i < lib.len; i++)
		if (lib.items[i].id == id)
			return &lib.items[i];

	return NULL;
}

static int join_path(char* out, size_t outsz, const char* a, const char* b)
{
	int n = snprintf(out, outsz, "%s/%s", a, b);
	if (n < 0)
		return -1;

	if ((size_t)n >= outsz)
		return -1;

	return 0;
}

static int parse_hex64(const char* s, uint64_t* out)
{
	char* end = NULL;

	if (!s || *s == '\0')
		return -1;

	errno = 0;
	unsigned long long v = strtoull(s, &end, 16);
	if (errno != 0)
		return -1;
	if (!end || *end != '\0')
		return -1;

	*out = (uint64_t)v;
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

static int stream_file(int c, const struct item* it)
{
	char full[4096];

	/* build absolute path */
	if (join_path(full, sizeof(full), media_dir, it->path) < 0) {
		LOG(verbose_log, "HTTP", "path too long");
		reply_text(c, HTTP_500, "server error\n");
		return -1;
	}

	/* open file */
	int fd = open(full, O_RDONLY);
	if (fd < 0) {
		LOG(verbose_log, "HTTP", "open failed: %s", it->path);
		reply_text(c, HTTP_404, "not found\n");
		return 0;
	}

	/* stat file */
	struct stat st;
	if (fstat(fd, &st) < 0) {
		close(fd);
		reply_text(c, HTTP_500, "server error\n");
		return -1;
	}

	/* reject non-regular files */
	if (!S_ISREG(st.st_mode)) {
		close(fd);
		reply_text(c, HTTP_404, "not found\n");
		return 0;
	}

	size_t len = (size_t)st.st_size;

	/* build response header */
	char resp[HTTP_RESP_MAX];
	int n = snprintf(
		resp, sizeof(resp),
		"%s"
		HTTP_BIN
		HTTP_LENGTH
		HTTP_CLOSE
		"\r\n",
		HTTP_200, len
	);

	if (n < 0) {
		close(fd);
		return -1;
	}

	if ((size_t)n >= sizeof(resp))
		n = (int)(sizeof(resp) - 1);

	/* send headers */
	(void)write_all(c, resp, (size_t)n);

	/* stream file */
	char buf[8192];
	for (;;) {
		ssize_t r = read(fd, buf, sizeof(buf));
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (r == 0)
			break;

		if (write_all(c, buf, (size_t)r) < 0)
			break;
	}

	close(fd);
	LOG(verbose_log, "HTTP", "streamed %s (%zu bytes)", it->path, len);

	return 0;
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
		struct json j;

		if (json_library(&j, &lib) < 0) {
			LOG(verbose_log, "JSON", "encode failed");
			reply_text(c, HTTP_500, "json failed\n");
			return -1;
		}
		LOG(verbose_log, "JSON", "encoded %zu bytes", j.len);

		reply_json(c, HTTP_200, j.buf, j.len);
		json_free(&j);

		return 0;
	}

	if (strncmp(path, "/stream/", 8) == 0) {
		LOG(verbose_log, "HTTP", "route /stream");

		uint64_t id;
		if (parse_hex64(path + 8, &id) < 0) {
			reply_text(c, HTTP_400, "bad request\n");
			return 0;
		}

		const struct item* it = find_item(id);
		if (!it) {
			reply_text(c, HTTP_404, "not found\n");
			return 0;
		}

		return stream_file(c, it);
	}

	LOG(verbose_log, "HTTP", "route not found: %s", path);
	reply_text(c, HTTP_404, "not found\n");

	return 0;
}

