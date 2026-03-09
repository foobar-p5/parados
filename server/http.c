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
#include <time.h>
#include <tinycthread.h>
#include <unistd.h>

#include "config.h"
#include "http.h"
#include "json.h"
#include "log.h"
#include "scan.h"
#include "users.h"
#include "util.h"

static int cors_build(char* out, size_t outsz, const char* hdr, int preflight);
static const struct item* find_item(uint64_t id);
static int item_path_for_id(char out[4096], uint64_t id, const struct user* u);
static const char* mime_from_path(const char* path);
static int parse_hex64(const char* s, uint64_t* out);
static int parse_range(const char* hdr, size_t total, size_t* start, size_t* end);
static int read_request(int c, char* method, size_t msz, char* path, size_t psz, char* hdr, size_t hsz);
static void reply(int c, const char* hdr, const char* status, const char* ctype, const char* extra, const void* body, size_t len, int send_body, int preflight);
static void reply_json(int c, const char* hdr, const char* status, const char* body, size_t len, int send_body);
static void reply_preflight(int c, const char* hdr);
static void reply_text(int c, const char* hdr, const char* status, const char* body);
static void reply_unauth(int c, const char* hdr, int send_body);
static int stat_item(const struct item* it, struct stat* st);
static int stream_file(int c, const struct item* it, const char* hdr, int head_only);

extern struct library lib;
extern mtx_t lib_lock;

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

static int cors_build(char* out, size_t outsz, const char* hdr, int preflight)
{
	char origin[512];

	if (!out || outsz == 0)
		return 0;

	out[0] = '\0';

	if (cors_origin[0] == '\0')
		return 0;

	if (hdr_get_value(origin, hdr, "origin") < 0)
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
			"Access-Control-Allow-Headers: Range, Content-Type, Authorization\r\n"
			"Access-Control-Max-Age: 600\r\n",

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
	if ((size_t)n >= outsz) {
		out[0] = '\0';
		return 0;
	}
	return 1;
}

static const struct item* find_item(uint64_t id)
{
	for (size_t i = 0; i < lib.len; i++)
		if (lib.items[i].id == id)
			return &lib.items[i];

	return NULL;
}

static int item_path_for_id(char out[4096], uint64_t id, const struct user* u)
{
	int ret = -1;

	if (!out)
		return -1;

	out[0] = '\0';

	mtx_lock(&lib_lock);

	const struct item* it = find_item(id);
	if (!it) {
		ret = 1; /* not found */
		goto out;
	}

	if (u && !user_allows_path(u, it->path)) {
		ret = 1; /* not found */
		goto out;
	}

	if (snprintf(out, 4096, "%s", it->path) >= 4096) {
		ret = -1;
		goto out;
	}

	ret = 0;

out:
	mtx_unlock(&lib_lock);
	return ret; /* 0 ok, 1 not found, -1 error */
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
	if (!s || !out)
		return -1;

	if (strlen(s) != 16)
		return -1;

	for (size_t i = 0; i < 16; i++) {
		unsigned char c = (unsigned char)s[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
			return -1;
	}

	char* end = NULL;
	errno = 0;
	unsigned long long v = strtoull(s, &end, 16);
	if (errno != 0 || !end || *end != '\0')
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

static void reply(int c, const char* hdr, const char* status, const char* ctype, const char* extra, const void* body, size_t len, int send_body, int preflight)
{
	char resp[HTTP_RESP_MAX];
	char cors[512];

	(void)cors_build(cors, sizeof(cors), hdr, preflight);

	int n = snprintf(
		resp, sizeof(resp),

		"%s"
		"%s"
		"%s"
		"%s"
		HTTP_LENGTH
		HTTP_CLOSE
		"\r\n",

		status,
		cors,
		(ctype && ctype[0]) ? ctype : "",
		(extra && extra[0]) ? extra : "",
		len
	);

	if (n < 0)
		return;

	if ((size_t)n >= sizeof(resp)) {
		/* fail if header too large */
		reply_text(c, hdr, HTTP_500, "Server Error\n");
		return;
	}

	(void)write_all(c, resp, (size_t)n);

	if (send_body && body && len > 0)
		(void)write_all(c, body, len);
}

static void reply_json(int c, const char* hdr, const char* status, const char* body, size_t len, int send_body)
{
	reply(c, hdr, status, HTTP_JSON, NULL, body, len, send_body, 0);
}

static void reply_preflight(int c, const char* hdr)
{
	reply(c, hdr, HTTP_204, NULL, NULL, NULL, (size_t)0, 0, 1);
}

static void reply_text(int c, const char* hdr, const char* status, const char* body)
{
	size_t len = strlen(body);
	reply(c, hdr, status, HTTP_TEXT, NULL, body, len, 1, 0);
}

static void reply_unauth(int c, const char* hdr, int send_body)
{
	const char* body = "unauthorized\n";
	size_t blen = strlen(body);

	reply(
		c, hdr,
		"HTTP/1.1 401 Unauthorized\r\n",
		HTTP_TEXT,
		"WWW-Authenticate: Basic realm=\"parados\"\r\n",
		body,
		blen,
		send_body,
		0
	);
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
		LOG(verbose_log, "HTTP", "Stream FAILED      Path too long");
		reply_text(c, hdr, HTTP_500, "Server Error\n");
		return -1;
	}

	/* open file */
	int fd = open(full, O_RDONLY);
	if (fd < 0) {
		LOG(verbose_log, "HTTP", "Open FAILED        %s", it->path);
		reply_text(c, hdr, HTTP_404, "Not Found\n");
		return 0;
	}

	/* stat file */
	struct stat st;
	if (fstat(fd, &st) < 0) {
		close(fd);
		reply_text(c, hdr, HTTP_500, "Server Error\n");
		return -1;
	}

	/* reject non-regular files */
	if (!S_ISREG(st.st_mode)) {
		close(fd);
		reply_text(c, hdr, HTTP_404, "Not Found\n");
		return 0;
	}

	size_t total = (size_t)st.st_size;
	size_t start = 0;
	size_t end = total ? (total - 1) : 0;
	const char* type = mime_from_path(it->path);

	int partial = parse_range(hdr, total, &start, &end);
	if (partial == RANGE_BAD) {
		close(fd);
		reply_text(c, hdr, HTTP_400, "Bad Range\n");
		return 0;
	}

	if (partial == RANGE_UNSAT) {
		close(fd);
		reply_text(c, hdr, HTTP_416, "Range Not Satisfiable\n");
		return 0;
	}

	if (partial == RANGE_OK) {
		if (lseek(fd, (off_t)start, SEEK_SET) < 0) {
			close(fd);
			reply_text(c, hdr, HTTP_500, "Server Error\n");
			return -1;
		}
	}

	size_t len = (total == 0) ? 0 : (end - start + 1);

	/* build response header */
	char ctype[128];
	char extra[256];

	if (snprintf(ctype, sizeof(ctype), HTTP_CTYPE, type) >= (int)sizeof(ctype)) {
		close(fd);
		reply_text(c, hdr, HTTP_500, "Server Error\n");
		return -1;
	}

	if (partial == RANGE_OK) {
		/* partial */
		if (snprintf(
			extra, sizeof(extra),
			HTTP_RANGE
			HTTP_CRG,
			start, end, total
		) >= (int)sizeof(extra)) {
			close(fd);
			reply_text(c, hdr, HTTP_500, "Server Error\n");
			return -1;
		}

		reply(c, hdr, HTTP_206, ctype, extra, NULL, len, 0, 0);
	}
	else {
		/* non-partial */
		if (snprintf(extra, sizeof(extra), HTTP_RANGE) >= (int)sizeof(extra)) {
			close(fd);
			reply_text(c, hdr, HTTP_500, "Server Error\n");
			return -1;
		}

		reply(c, hdr, HTTP_200, ctype, extra, NULL, len, 0, 0);
	}

	/* HEAD: no body */
	if (head_only) {
		close(fd);

		if (partial == RANGE_OK)
			LOG(verbose_log, "HTTP", "Header             %s [%zu-%zu/%zu]", it->path, start, end, total);
		else
			LOG(verbose_log, "HTTP", "Header             %s (%zu bytes)", it->path, total);

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
		LOG(verbose_log, "HTTP", "Streamed           %s [%zu-%zu/%zu]", it->path, start, end, total);
	else
		LOG(verbose_log, "HTTP", "Streamed           %s (%zu bytes)", it->path, total);

	return 0;
}

int http_handle(int c)
{
	char method[16];
	char path[1024];
	char hdr[HTTP_REQ_MAX];

	const struct user* u = NULL;
	method[0] = '\0';
	path[0] = '\0';
	hdr[0] = '\0';

	if (read_request(c, method, sizeof(method), path, sizeof(path), hdr, sizeof(hdr)) < 0) {
		reply_text(c, hdr, HTTP_400, "Bad Request\n");
		return -1;
	}
	LOG(verbose_log, "HTTP", "Request            %s %s", method, path);

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
		LOG(verbose_log, "HTTP", "Method forbidden   %s", method);
		reply_text(c, hdr, HTTP_405, "Method Not Allowed\n");
		return 0;
	}

	if (strcmp(path, "/ping") == 0) {
		LOG(verbose_log, "HTTP", "Route              /ping");
		reply_text(c, hdr, HTTP_200, "OK\n");
		return 0;
	}

	if (users.len > 0) {
		u = users_auth_from_hdr(hdr);
		if (!u) {
			reply_unauth(c, hdr, !head_only);
			return 0;
		}
	}

	if (strcmp(path, "/library") == 0) {
		LOG(verbose_log, "HTTP", "Route              /library");

		mtx_lock(&lib_lock);

		struct json j;
		struct library view;
		memset(&view, 0, sizeof(view));

		if (!u) {
			view = lib;
		}
		else {
			if (lib.len > 0) {
				view.items = calloc(lib.len, sizeof(*view.items));
				if (!view.items) {
					mtx_unlock(&lib_lock);
					reply_text(c, hdr, HTTP_500, "Server Error\n");
					return -1;
				}
			}

			for (size_t i = 0; i < lib.len; i++) {
				if (!user_allows_path(u, lib.items[i].path))
					continue;
				view.items[view.len++] = lib.items[i];
			}
			view.cap = view.len;
		}

		if (json_library(&j, &view) < 0) {
			if (u)
				free(view.items);

			mtx_unlock(&lib_lock);

			LOG(verbose_log, "JSON", "Encode     FAILED");
			reply_text(c, hdr, HTTP_500, "JSON Encode Failed\n");
			return -1;
		}

		mtx_unlock(&lib_lock);

		LOG(verbose_log, "JSON", "Encoded bytes      %zu bytes", j.len);

		reply_json(c, hdr, HTTP_200, j.buf, j.len, !head_only);
		json_free(&j);

		if (u)
			free(view.items);

		return 0;
	}

	if (strcmp(path, "/rescan") == 0) {
		LOG(verbose_log, "HTTP", "Route              /rescan");

		if (users.len == 0) {
			LOG(true, "HTTP", "Rescan forbidden   Auth disabled");
			reply_text(c, hdr, HTTP_403, "Forbidden\n");
			return 0;
		}

		LOG(true, "SCAN", "Rescan requested   %s", u->name);

		struct timespec t0;
		struct timespec t1;
		clock_gettime(CLOCK_MONOTONIC, &t0);

		size_t before = 0;
		size_t after  = 0;

		mtx_lock(&lib_lock);

		before = lib.len;
		LOG(verbose_log, "SCAN", "Rescan begin       %s (%zu items)", media_dir, before);

		int ok = scan_library_rescan(&lib, media_dir);

		after = lib.len;

		mtx_unlock(&lib_lock);

		clock_gettime(CLOCK_MONOTONIC, &t1);

		long ms = (t1.tv_sec - t0.tv_sec) * 1000L +
			(t1.tv_nsec - t0.tv_nsec) / 1000000L;

		if (ok < 0) {
			LOG(true, "SCAN", "Rescan FAILED      %s (%ld ms)", media_dir, ms);
			reply_text(c, hdr, HTTP_500, "Rescan Failed\n");
			return -1;
		}

		LOG(true, "SCAN", "Rescan OK          %zu -> %zu (%ld ms)", before, after, ms);

		reply_text(c, hdr, HTTP_200, "OK\n");
		return 0;
	}

	if (strncmp(path, "/stream/", 8) == 0) {
		LOG(verbose_log, "HTTP", "Route              /stream");

		uint64_t id;
		if (parse_hex64(path + 8, &id) < 0) {
			reply_text(c, hdr, HTTP_400, "Bad Request\n");
			return 0;
		}

		char rel[4096];
		int fr = item_path_for_id(rel, id, u);
		if (fr == 1) {
			reply_text(c, hdr, HTTP_404, "Not Found\n");
			return 0;
		}
		if (fr < 0) {
			reply_text(c, hdr, HTTP_500, "Server Error\n");
			return -1;
		}

		struct item tmp;
		tmp.id = id;
		tmp.path = rel;

		return stream_file(c, &tmp, hdr, head_only);
	}

	if (strncmp(path, "/meta/", 6) == 0) {
		LOG(verbose_log, "HTTP", "Route              /meta");

		uint64_t id;
		if (parse_hex64(path + 6, &id) < 0) {
			reply_text(c, hdr, HTTP_400, "Bad Request\n");
			return 0;
		}

		char rel[4096];
		int fr = item_path_for_id(rel, id, u);
		if (fr == 1) {
			reply_text(c, hdr, HTTP_404, "Not Found\n");
			return 0;
		}

		if (fr < 0) {
			reply_text(c, hdr, HTTP_500, "Server Error\n");
			return -1;
		}

		struct item tmp;
		tmp.id = id;
		tmp.path = rel;

		struct stat st;
		if (stat_item(&tmp, &st) < 0) {
			reply_text(c, hdr, HTTP_404, "Not Found\n");
			return 0;
		}

		const char* type = mime_from_path(rel);

		struct json j;
		if (json_meta(&j, &tmp, (size_t)st.st_size, (long)st.st_mtime, type) < 0) {
			reply_text(c, hdr, HTTP_500, "JSON Failed\n");
			return -1;
		}

		reply_json(c, hdr, HTTP_200, j.buf, j.len, !head_only);
		json_free(&j);

		return 0;
	}

	LOG(verbose_log, "HTTP", "Route not found    %s", path);
	reply_text(c, hdr, HTTP_404, "Not Found\n");

	return 0;
}

