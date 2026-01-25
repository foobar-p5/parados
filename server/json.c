#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "json.h"
#include "log.h"

static int json_grow(struct json* j, size_t need);
static int json_hex64(struct json* j, uint64_t v);
static int json_putc(struct json* j, const char c);
static int json_putn(struct json* j, const char* s, size_t n);
static int json_puts(struct json* j, const char* s);
static int json_string(struct json* j, const char* s);

static int json_grow(struct json* j, size_t need)
{
	if (j->len + need <= j->cap)
		return 0;

	size_t ncap = j->cap ? j->cap : 1024; /* initial buffer */
	while (ncap < j->len + need)
		ncap *= 2;

	char* nb = realloc(j->buf, ncap);
	if (!nb) {
		logmsg(verbose_log, "JSON", "out of memory");
		return -1;
	}

	j->buf = nb;
	j->cap = ncap;

	return 0;
}

static int json_hex64(struct json* j, uint64_t v)
{
	char hex[17];
	static const char* b16 = "0123456789abcdef";

	for (int i = 15; i >= 0; i--) {
		hex[i] = b16[v & 0xf];
		v >>= 4;
	}
	hex[16] = '\0';

	return json_string(j, hex);
}

static int json_putc(struct json* j, char c)
{
	return json_putn(j, &c, 1);
}

static int json_putn(struct json* j, const char* s, size_t n)
{
	if (json_grow(j, n + 1) < 0)
		return -1;

	memcpy(j->buf + j->len, s, n);
	j->len += n;
	j->buf[j->len] = '\0';

	return 0;
}

static int json_puts(struct json* j, const char* s)
{
	return json_putn(j, s, strlen(s));
}

static int json_string(struct json* j, const char* s)
{
	/* opening quote */
	if (json_putc(j, '"') < 0)
		return -1;

	/* emit string body */
	for (; *s; s++) {
		unsigned char c = (unsigned char)(*s);

		/* escape quote and backslash */
		if (c == '"' || c == '\\') {
			if (json_putc(j, '\\') < 0)
				return -1;
			if (json_putc(j, (char)c) < 0)
				return -1;
			continue;
		}

		/* common escapes */
		if (c == '\n') {
			if (json_puts(j, "\\n") < 0)
				return -1;
			continue;
		}
		if (c == '\r') {
			if (json_puts(j, "\\r") < 0)
				return -1;
			continue;
		}
		if (c == '\t') {
			if (json_puts(j, "\\t") < 0)
				return -1;
			continue;
		}

		/* other control chars->\uxxxx */
		if (c < 0x20) {
			char esc[7];
			snprintf(esc, sizeof(esc), "\\u%04x", (unsigned)c);
			if (json_puts(j, esc) < 0)
				return -1;
			continue;
		}

		/* literal byte */
		if (json_putc(j, (char)c) < 0)
			return -1;
	}

	/* closing quote */
	if (json_putc(j, '"') < 0)
		return -1;

	return 0;
}

int json_library(struct json* j, const struct library* l)
{
	memset(j, 0, sizeof(*j));

	/* header */
	if (json_puts(j, "{\"proto\":1,\"items\":[") < 0)
		goto fail;

	/* items[] */
	for (size_t i = 0; i < l->len; i++) {
		/* item separator */
		if (i > 0) {
			if (json_putc(j, ',') < 0)
				goto fail;
		}

		/* object open */
		if (json_puts(j, "{\"id\":") < 0)
			goto fail;
		if (json_hex64(j, l->items[i].id) < 0)
			goto fail;

		/* path */
		if (json_puts(j, ",\"path\":") < 0)
			goto fail;
		if (json_string(j, l->items[i].path) < 0)
			goto fail;

		/* object close */
		if (json_putc(j, '}') < 0)
			goto fail;
	}

	/* footer */
	if (json_puts(j, "]}") < 0)
		goto fail;

	return 0;

fail:
	json_free(j);
	return -1;
}

void json_free(struct json* j)
{
	if (!j)
		return;

	free(j->buf);
	j->buf = NULL;
	j->len = 0;
	j->cap = 0;
}

