#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "scan.h"
#include "log.h"

static uint64_t encode_fnv1a64(const char* s);
static int join_path(char* out, size_t outsz, const char* a, const char* b);
static int library_push(struct library* l, const char* rel);
static int scan_dir(struct library* l, const char* root, const char* rel);

static uint64_t encode_fnv1a64(const char* s)
{
	/* standard fnv1a64 encoding */
	uint64_t h = 1469598103934665603ULL;

	for (; *s; s++) {
		h ^= (unsigned char)(*s);
		h *= 1099511628211ULL;
	}

	return h;
}

static int join_path(char* out, size_t outsz, const char* a, const char* b)
{
	size_t al = strlen(a);
	size_t bl = strlen(b);

	if (al + 1 + bl + 1 > outsz) {
		logmsg(verbose_log, "SCAN", "path too long");
		return -1;
	}

	memcpy(out, a, al);
	out[al] = '/';
	memcpy(out + al + 1, b, bl);
	out[al + 1 + bl] = '\0';

	return 0;
}

static int library_push(struct library* l, const char* rel)
{
	if (l->len == l->cap) {
		size_t ncap = l->cap ? (l->cap * 2) : 64;
		struct item* ni = realloc(l->items, ncap * sizeof(*ni));
		if (!ni) {
			logmsg(verbose_log, "SCAN", "out of memory");
			return -1;
		}
		l->items = ni;
		l->cap = ncap;
	}

	char* p = strdup(rel);
	if (!p)
		return -1;

	l->items[l->len].id = encode_fnv1a64(rel);
	l->items[l->len].path = p;
	l->len++;

	return 0;
}

static int scan_dir(struct library* l, const char* root, const char* rel)
{
	char full[4096];
	DIR* d;
	struct dirent* e;

	if (rel[0] == '\0') {
		if (snprintf(full, sizeof(full), "%s", root) >= (int)sizeof(full))
			return -1;
	}
	else {
		if (join_path(full, sizeof(full), root, rel) < 0)
			return -1;
	}

	d = opendir(full);
	if (!d) {
		logmsg(verbose_log, "SCAN", "opendir failed: %s", full);
		return -1;
	}

	while ((e = readdir(d)) != NULL) {
		if (strcmp(e->d_name, ".") == 0)
			continue;
		if (strcmp(e->d_name, "..") == 0)
			continue;

		char rel2[4096];
		char full2[4096];

		if (rel[0] == '\0') {
			if (snprintf(rel2, sizeof(rel2), "%s", e->d_name) >= (int)sizeof(rel2))
				goto fail;
		}
		else {
			if (join_path(rel2, sizeof(rel2), rel, e->d_name) < 0)
				goto fail;
		}

		if (join_path(full2, sizeof(full2), root, rel2) < 0)
			goto fail;

		struct stat st;
		if (lstat(full2, &st) < 0)
			continue;

		if (S_ISDIR(st.st_mode)) {
			if (scan_dir(l, root, rel2) < 0)
				goto fail;
			continue;
		}

		if (S_ISREG(st.st_mode)) {
			if (library_push(l, rel2) < 0)
				goto fail;
			continue;
		}
	}

	closedir(d);
	return 0;

fail:
	closedir(d);
	return -1;
}

int scan_library(struct library* l, const char* root)
{
	memset(l, 0, sizeof(*l));
	return scan_dir(l, root, "");
}

void scan_library_free(struct library* l)
{
	if (!l)
		return;

	for (size_t i = 0; i < l->len; i++)
		free(l->items[i].path);

	free(l->items);

	l->items = NULL;
	l->len = 0;
	l->cap = 0;
}

