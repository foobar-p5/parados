#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "http.h"
#include "json.h"
#include "log.h"
#include "scan.h"

static const char* cistrstr(const char* hay, const char* nee);
static int cors_build(char* out, size_t outsz, const char* hdr, int preflight);
static int get_host(char out[512], const char* hdr);
static const struct item* find_item(uint64_t id);
static int join_path(char* out, size_t outsz, const char* a, const char* b);
static const char* mime_from_path(const char* path);
static int parse_hex64(const char* s, uint64_t* out);
static int parse_range(const char* hdr, size_t total, size_t* start, size_t* end);
static int read_request(int c, char* method, size_t msz, char* path, size_t psz, char* hdr, size_t hsz);
static void reply_json(int c, const char* hdr, const char* status, const char* body, size_t len, int send_body);
static void reply_m3u(int c, const char* hdr, const char* status, size_t len);
static void reply_preflight(int c, const char* hdr);
static void reply_text(int c, const char* hdr, const char* status, const char* body);
static int queue_write(int c, const char* hdr, int head_only);
static int stat_item(const struct item* it, struct stat* st);
static int stream_file(int c, const struct item* it, const char* hdr, int head_only);
static int write_all(int fd, const void* buf, size_t n);


extern struct library lib;

static const char* cistrstr(const char* hay, const char* nee)
{
	size_t nl = strlen(nee);
	if (nl == 0)
		return hay;

	for (; *hay; hay++) {
		size_t i = 0;

		for (;;) {
			if (i == nl)
				return hay;

			unsigned char a = (unsigned char)hay[i];
			unsigned char b = (unsigned char)nee[i];

			if (a == '\0')
				break;

			if (tolower(a) != tolower(b))
				break;

			i++;
		}
	}

	return NULL;
}

static int cors_origin_allowed(const char* origin)
{
	if (cors_origin[0] == '\0')
		return 0;

	if (strcmp(cors_origin, "*") == 0)
		return 1;

	/* comma/space separated allowlist */
	const char* p = cors_origin;
	while (*p) {
		while (*p == ' ' || *p == '\t' || *p == ',')
			p++;

		const char* s = p;
		while (*p && *p != ',')
			p++;

		const char* e = p;
		while (e > s && (e[-1] == ' ' || e[-1] == '\t'))
			e--;

		size_t n = (size_t)(e - s);
		if (n > 0 && strlen(origin) == n && strncmp(origin, s, n) == 0)
			return 1;

		if (*p == ',')
			p++;
	}

	return 0;
}

static int cors_get_origin(char out[512], const char* hdr)
{
	const char* p = cistrstr(hdr, "\norigin:");
	if (!p)
		p = cistrstr(hdr, "\rorigin:");
	if (!p)
		p = cistrstr(hdr, "origin:");
	if (!p)
		return -1;

	p = strchr(p, ':');
	if (!p)
		return -1;
	p++;

	while (*p == ' ' || *p == '\t')
		p++;

	size_t n = 0;
	while (*p && *p != '\r' && *p != '\n') {
		if (n + 1 >= 512)
			return -1;
		out[n++] = *p++;
	}
	out[n] = '\0';

	if (n == 0)
		return -1;

	return 0;
}

static int cors_build(char* out, size_t outsz, const char* hdr, int preflight)
{
	char origin[512];

	if (!out || outsz == 0)
		return 0;

	out[0] = '\0';

	if (cors_origin[0] == '\0')
		return 0;

	if (cors_get_origin(origin, hdr) < 0)
		return 0;

	if (!cors_origin_allowed(origin))
		return 0;

	int n;
	const char* ao = (strcmp(cors_origin, "*") == 0) ? "*" : origin;
	if (preflight) {
		n = snprintf(
			out, outsz,
			"Access-Control-Allow-Origin: %s\r\n"
			"Vary: Origin\r\n"
			"Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\n"
			"Access-Control-Allow-Headers: Range, Content-Type\r\n"
			"Access-Control-Max-Age: 600\r\n"
			"Access-Control-Expose-Headers: Content-Length, Content-Range, Accept-Ranges, Content-Type\r\n",
			ao
		);
	}
	else {
		n = snprintf(
			out, outsz,
			"Access-Control-Allow-Origin: %s\r\n"
			"Vary: Origin\r\n"
			"Access-Control-Expose-Headers: Content-Length, Content-Range, Accept-Ranges, Content-Type\r\n",
			ao
		);
	}

	if (n < 0)
		return 0;
	if ((size_t)n >= outsz)
		out[outsz - 1] = '\0';

	return 1;
}

static int get_host(char out[512], const char* hdr)
{
	const char* p = cistrstr(hdr, "\nhost:");
	if (!p)
		p = cistrstr(hdr, "\rhost:");
	if (!p)
		p = cistrstr(hdr, "host:");
	if (!p)
		return -1;

	p = strchr(p, ':');
	if (!p)
		return -1;
	p++;

	while (*p == ' ' || *p == '\t')
		p++;

	size_t n = 0;
	while (*p && *p != '\r' && *p != '\n') {
		if (n + 1 >= 512)
			return -1;
		out[n++] = *p++;
	}
	out[n] = '\0';

	if (n == 0)
		return -1;

	return 0;
}

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

static const char* mime_from_path(const char* path)
{
	const char* dot = strrchr(path, '.');
	if (!dot || dot[1] == '\0')
		return "application/octet-stream";

	dot++;

	/* audio */
	if (strcasecmp(dot, "mp3") == 0)
		return "audio/mpeg";
	if (strcasecmp(dot, "m4a") == 0)
		return "audio/mp4";
	if (strcasecmp(dot, "aac") == 0)
		return "audio/aac";
	if (strcasecmp(dot, "flac") == 0)
		return "audio/flac";
	if (strcasecmp(dot, "wav") == 0)
		return "audio/wav";
	if (strcasecmp(dot, "ogg") == 0)
		return "audio/ogg";
	if (strcasecmp(dot, "opus") == 0)
		return "audio/opus";

	/* video */
	if (strcasecmp(dot, "mp4") == 0)
		return "video/mp4";
	if (strcasecmp(dot, "mkv") == 0)
		return "video/x-matroska";
	if (strcasecmp(dot, "webm") == 0)
		return "video/webm";
	if (strcasecmp(dot, "mov") == 0)
		return "video/quicktime";

	/* images */
	if (strcasecmp(dot, "jpg") == 0)
		return "image/jpeg";
	if (strcasecmp(dot, "jpeg") == 0)
		return "image/jpeg";
	if (strcasecmp(dot, "png") == 0)
		return "image/png";
	if (strcasecmp(dot, "gif") == 0)
		return "image/gif";
	if (strcasecmp(dot, "webp") == 0)
		return "image/webp";

	/* misc */
	if (strcasecmp(dot, "pdf") == 0)
		return "application/pdf";

	return "application/octet-stream";
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

static int parse_range(const char* hdr, size_t total, size_t* start, size_t* end)
{
	const char* p = cistrstr(hdr, "\nrange:");
	if (!p)
		p = cistrstr(hdr, "\rrange:");
	if (!p)
		p = cistrstr(hdr, "range:");
	if (!p)
		return RANGE_NONE;

	const char* q = cistrstr(p, "bytes=");
	if (!q)
		return RANGE_BAD;
	q += 6;

	while (*q == ' ')
		q++;

	if (*q == '-') {
		/* bytes=-SUFFIX */
		const char* r = q + 1;
		char* e2 = NULL;

		errno = 0;
		unsigned long long suf = strtoull(r, &e2, 10);
		if (errno != 0 || e2 == r)
			return RANGE_BAD;
		if (suf == 0)
			return RANGE_BAD;

		if (total == 0)
			return RANGE_UNSAT;

		if ((size_t)suf >= total) {
			*start = 0;
			*end = total - 1;
			return RANGE_OK;
		}

		*start = total - (size_t)suf;
		*end = total - 1;
		return RANGE_OK;
	}

	/* bytes=START- or bytes=START-END */
	char* e1 = NULL;

	errno = 0;
	unsigned long long a = strtoull(q, &e1, 10);
	if (errno != 0 || e1 == q)
		return RANGE_BAD;

	if (*e1 != '-')
		return RANGE_BAD;

	const char* r = e1 + 1;

	if (*r == '\r' || *r == '\n' || *r == '\0') {
		/* bytes=START- */
		if ((size_t)a >= total)
			return RANGE_UNSAT;
		*start = (size_t)a;
		*end = total - 1;
		return RANGE_OK;
	}

	char* e2 = NULL;

	errno = 0;
	unsigned long long b = strtoull(r, &e2, 10);
	if (errno != 0 || e2 == r)
		return RANGE_BAD;

	if ((size_t)a >= total)
		return RANGE_UNSAT;
	if ((size_t)b >= total)
		b = total - 1;
	if (b < a)
		return RANGE_BAD;

	*start = (size_t)a;
	*end = (size_t)b;
	return RANGE_OK;
}

static int read_request(int c, char* method, size_t msz, char* path, size_t psz, char* hdr, size_t hsz)
{
	size_t used = 0;

	for (;;) {
		if (used + 1 >= hsz)
			return -1;

		ssize_t r = read(c, hdr + used, hsz - 1 - used);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (r == 0)
			return -1;

		used += (size_t)r;
		hdr[used] = '\0';

		if (strstr(hdr, "\r\n\r\n"))
			break;
	}

	char* eol = strstr(hdr, "\r\n");
	if (!eol)
		return -1;
	*eol = '\0';

	if (sscanf(hdr, "%15s %1023s", method, path) != 2)
		return -1;

	method[msz-1] = '\0';
	path[psz-1] = '\0';

	*eol = '\r';

	return 0;
}

static void reply_json(int c, const char* hdr, const char* status, const char* body, size_t len, int send_body)
{
	char resp[HTTP_RESP_MAX];
	char cors[512];

	(void)cors_build(cors, sizeof(cors), hdr, 0);
	int n = snprintf(
		resp, sizeof(resp),

		"%s"
		"%s"
		HTTP_JSON
		HTTP_LENGTH
		HTTP_CLOSE
		"\r\n",

		status, cors, len
	);

	if (n < 0)
		return;

	if ((size_t)n >= sizeof(resp))
		n = (int)(sizeof(resp) - 1);

	(void)write_all(c, resp, (size_t)n);

	if (send_body)
		(void)write_all(c, body, len);
}


static void reply_m3u(int c, const char* hdr, const char* status, size_t len)
{
	char resp[HTTP_RESP_MAX];
	char cors[512];

	(void)cors_build(cors, sizeof(cors), hdr, 0);
	int n = snprintf(
		resp, sizeof(resp),

		"%s"
		"%s"
		HTTP_M3U
		HTTP_LENGTH
		HTTP_CLOSE
		"\r\n",

		status, cors, len
	);

	if (n < 0)
		return;

	if ((size_t)n >= sizeof(resp))
		n = (int)(sizeof(resp) - 1);

	(void)write_all(c, resp, (size_t)n);
}

static void reply_preflight(int c, const char* hdr)
{
	char resp[HTTP_RESP_MAX];
	char cors[512];

	(void)cors_build(cors, sizeof(cors), hdr, 1);

	int n = snprintf(
		resp, sizeof(resp),
		"%s"
		"%s"
		HTTP_LENGTH
		HTTP_CLOSE
		"\r\n",
		HTTP_204,
		cors,
		(size_t)0
	);

	if (n < 0)
		return;
	if ((size_t)n >= sizeof(resp))
		n = (int)(sizeof(resp) - 1);

	(void)write_all(c, resp, (size_t)n);
}

static void reply_text(int c, const char* hdr, const char* status, const char* body)
{
	char resp[HTTP_RESP_MAX];
	char cors[512];

	(void)cors_build(cors, sizeof(cors), hdr, 0);
	int n = snprintf(
		resp, sizeof(resp),

		"%s"
		"%s"
		HTTP_TEXT
		HTTP_LENGTH
		HTTP_CLOSE
		"\r\n"
		"%s",

		status,
		cors,
		strlen(body), body
	);

	if (n < 0)
		return;

	if ((size_t)n >= sizeof(resp))
		n = (int)(sizeof(resp) - 1);

	(void)write_all(c, resp, (size_t)n);
}

static int queue_write(int c, const char* hdr, int head_only)
{
	char host[512];
	char base[768];

	if (get_host(host, hdr) == 0) {
		if (snprintf(base, sizeof(base), "http://%s", host) >= (int)sizeof(base))
			return -1;
	}
	else {
		if (snprintf(base, sizeof(base), "http://%s:%d", server_addr, server_port) >= (int)sizeof(base))
			return -1;
	}

	/* Content-Length */
	size_t len = 0;
	len += 8; /* "#EXTM3U\n" */

	for (size_t i = 0; i < lib.len; i++) {
		int n = snprintf(
			NULL, 0,
			"%s/stream/%016llx\n",
			base,
			(unsigned long long)lib.items[i].id
		);

		if (n < 0)
			return -1;

		len += (size_t)n;
	}

	reply_m3u(c, hdr, HTTP_200, len);

	if (head_only)
		return 0;

	if (write_all(c, "#EXTM3U\n", 8) < 0)
		return -1;

	for (size_t i = 0; i < lib.len; i++) {
		char line[2048];

		int n = snprintf(
			line, sizeof(line),
			"%s/stream/%016llx\n",
			base,
			(unsigned long long)lib.items[i].id
		);

		if (n < 0)
			return -1;
		if ((size_t)n >= sizeof(line))
			return -1;

		if (write_all(c, line, (size_t)n) < 0)
			return -1;
	}

	return 0;
}

static int stat_item(const struct item* it, struct stat* st)
{
	char full[4096];

	if (join_path(full, sizeof(full), media_dir, it->path) < 0)
		return -1;

	if (stat(full, st) < 0)
		return -1;

	if (!S_ISREG(st->st_mode))
		return -1;

	return 0;
}

static int stream_file(int c, const struct item* it, const char* hdr, int head_only)
{
	char full[4096];

	/* build absolute path */
	if (join_path(full, sizeof(full), media_dir, it->path) < 0) {
		LOG(verbose_log, "HTTP", "path too long");
		reply_text(c, hdr, HTTP_500, "server error\n");
		return -1;
	}

	/* open file */
	int fd = open(full, O_RDONLY);
	if (fd < 0) {
		LOG(verbose_log, "HTTP", "open failed: %s", it->path);
		reply_text(c, hdr, HTTP_404, "not found\n");
		return 0;
	}

	/* stat file */
	struct stat st;
	if (fstat(fd, &st) < 0) {
		close(fd);
		reply_text(c, hdr, HTTP_500, "server error\n");
		return -1;
	}

	/* reject non-regular files */
	if (!S_ISREG(st.st_mode)) {
		close(fd);
		reply_text(c, hdr, HTTP_404, "not found\n");
		return 0;
	}

	size_t total = (size_t)st.st_size;
	size_t start = 0;
	size_t end = total ? (total - 1) : 0;
	const char* type = mime_from_path(it->path);
	char cors[512];

	(void)cors_build(cors, sizeof(cors), hdr, 0);

	int partial = parse_range(hdr, total, &start, &end);
	if (partial == RANGE_BAD) {
		close(fd);
		reply_text(c, hdr, HTTP_400, "bad range\n");
		return 0;
	}

	if (partial == RANGE_UNSAT) {
		close(fd);
		reply_text(c, hdr, HTTP_416, "range not satisfiable\n");
		return 0;
	}

	if (partial == RANGE_OK) {
		if (lseek(fd, (off_t)start, SEEK_SET) < 0) {
			close(fd);
			reply_text(c, hdr, HTTP_500, "server error\n");
			return -1;
		}
	}

	size_t len = (total == 0) ? 0 : (end - start + 1);

	/* build response header */
	char resp[HTTP_RESP_MAX];
	int n;

	if (partial == RANGE_OK) {
		/* partial */
		n = snprintf(
			resp, sizeof(resp),
			"%s"
			HTTP_CTYPE
			"%s"
			HTTP_RANGE
			HTTP_CRG
			HTTP_LENGTH
			HTTP_CLOSE
			"\r\n",
			HTTP_206, type, cors, start, end, total, len
		);
	}
	else {
		/* non-partial */
		n = snprintf(
			resp, sizeof(resp),
			"%s"
			HTTP_CTYPE
			"%s"
			HTTP_RANGE
			HTTP_LENGTH
			HTTP_CLOSE
			"\r\n",
			HTTP_200, type, cors, len
		);
	}

	if (n < 0) {
		close(fd);
		return -1;
	}

	if ((size_t)n >= sizeof(resp))
		n = (int)(sizeof(resp) - 1);

	/* send headers */
	(void)write_all(c, resp, (size_t)n);

	/* HEAD: no body */
	if (head_only) {
		close(fd);

		if (partial == RANGE_OK)
			LOG(verbose_log, "HTTP", "header %s [%zu-%zu/%zu]", it->path, start, end, total);
		else
			LOG(verbose_log, "HTTP", "header %s (%zu bytes)", it->path, total);

		return 0;
	}

	/* stream file */
	char buf[8192];
	size_t left = len;

	while (left > 0) {
		size_t want = sizeof(buf);
		if (want > left)
			want = left;

		ssize_t r = read(fd, buf, want);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (r == 0)
			break;

		if (write_all(c, buf, (size_t)r) < 0)
			break;

		left -= (size_t)r;
	}

	close(fd);

	if (partial == RANGE_OK)
		LOG(verbose_log, "HTTP", "streamed %s [%zu-%zu/%zu]", it->path, start, end, total);
	else
		LOG(verbose_log, "HTTP", "streamed %s (%zu bytes)", it->path, total);

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
	char hdr[HTTP_REQ_MAX];

	if (read_request(c, method, sizeof(method), path, sizeof(path), hdr, sizeof(hdr)) < 0) {
		reply_text(c, hdr, HTTP_400, "bad request\n");
		return -1;
	}
	LOG(verbose_log, "HTTP", "request: %s %s", method, path);

	int head_only = 0;
	if (strcmp(method, "GET") == 0) {
		head_only = 0;
	}
	else if (strcmp(method, "HEAD") == 0) {
		head_only = 1;
	}
	else if (strcmp(method, "OPTIONS") == 0) {
		reply_preflight(c, hdr);
		return 0;
	}
	else {
		LOG(verbose_log, "HTTP", "method not allowed: %s", method);
		reply_text(c, hdr, HTTP_405, "method not allowed\n");
		return 0;
	}

	if (strcmp(path, "/ping") == 0) {
		LOG(verbose_log, "HTTP", "route /ping");
		reply_text(c, hdr, HTTP_200, "ok\n");
		return 0;
	}

	if (strcmp(path, "/library") == 0) {
		LOG(verbose_log, "HTTP", "route /library");
		struct json j;

		if (json_library(&j, &lib) < 0) {
			LOG(verbose_log, "JSON", "encode failed");
			reply_text(c, hdr, HTTP_500, "json failed\n");
			return -1;
		}
		LOG(verbose_log, "JSON", "encoded %zu bytes", j.len);

		reply_json(c, hdr, HTTP_200, j.buf, j.len, !head_only);
		json_free(&j);

		return 0;
	}

	if (strncmp(path, "/stream/", 8) == 0) {
		LOG(verbose_log, "HTTP", "route /stream");

		uint64_t id;
		if (parse_hex64(path + 8, &id) < 0) {
			reply_text(c, hdr, HTTP_400, "bad request\n");
			return 0;
		}

		const struct item* it = find_item(id);
		if (!it) {
			reply_text(c, hdr, HTTP_404, "not found\n");
			return 0;
		}

		return stream_file(c, it, hdr, head_only);
	}

	if (strncmp(path, "/meta/", 6) == 0) {
		LOG(verbose_log, "HTTP", "route /meta");

		uint64_t id;
		if (parse_hex64(path + 6, &id) < 0) {
			reply_text(c, hdr, HTTP_400, "bad request\n");
			return 0;
		}

		const struct item* it = find_item(id);
		if (!it) {
			reply_text(c, hdr, HTTP_404, "not found\n");
			return 0;
		}

		struct stat st;
		if (stat_item(it, &st) < 0) {
			reply_text(c, hdr, HTTP_404, "not found\n");
			return 0;
		}

		const char* type = mime_from_path(it->path);

		struct json j;
		if (json_meta(&j, it, (size_t)st.st_size, type) < 0) {
			reply_text(c, hdr, HTTP_500, "json failed\n");
			return -1;
		}

		reply_json(c, hdr, HTTP_200, j.buf, j.len, !head_only);
		json_free(&j);

		return 0;
	}

	if (strcmp(path, "/queue") == 0) {
		LOG(verbose_log, "HTTP", "route /queue");

		if (queue_write(c, hdr, head_only) < 0) {
			reply_text(c, hdr, HTTP_500, "server error\n");
			return -1;
		}

		return 0;
	}

	LOG(verbose_log, "HTTP", "route not found: %s", path);
	reply_text(c, hdr, HTTP_404, "not found\n");

	return 0;
}

