#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "config.h"
#include "log.h"
#include "users.h"

static int load_path(const char* path);
static int parse_bool(const char* s, bool* out);
static int set_kv(const char* k, const char* v);
static char* trim(char* s);

/* defaults */
char media_dir[4096] = "/mnt/sto/Media/";
char server_addr[64] = "127.0.0.1";
int  server_port = 8088;
bool verbose_log = true;
char cors_origin[1024] = "";
int http_io_timeout = 5;
int max_clients = 64;

static int load_path(const char* path)
{
	FILE* f = fopen(path, "r");
	if (!f)
		return -1;

	char* line = NULL;
	size_t cap = 0;
	ssize_t n;

	while ((n = getline(&line, &cap, f)) >= 0) {
		(void)n;

		char* s = trim(line);
		if (s[0] == '\0')
			continue;
		if (s[0] == '#')
			continue;

		char* eq = strchr(s, '=');
		if (!eq)
			continue;

		*eq = '\0';
		char* k = trim(s);
		char* v = trim(eq + 1);

		if (k[0] == '\0')
			continue;

		(void)set_kv(k, v);
	}

	free(line);
	fclose(f);
	return 0;
}

static int parse_bool(const char* s, bool* out)
{
	if (!s || !out)
		return -1;

	if (strcmp(s, "1") == 0 || strcasecmp(s, "true") == 0 || strcasecmp(s, "yes") == 0)
		*out = true;
	else if (strcmp(s, "0") == 0 || strcasecmp(s, "false") == 0 || strcasecmp(s, "no") == 0)
		*out = false;
	else
		return -1;

	return 0;
}

static int set_kv(const char* k, const char* v)
{
	/* regular */
	if (strcmp(k, "media_dir") == 0) {
		snprintf(media_dir, sizeof(media_dir), "%s", v);
		return 0;
	}

	if (strcmp(k, "server_addr") == 0) {
		snprintf(server_addr, sizeof(server_addr), "%s", v);
		return 0;
	}

	if (strcmp(k, "server_port") == 0) {
		char* end = NULL;
		long p = strtol(v, &end, 10);
		if (!end || *end != '\0')
			return -1;

		if (p < 1 || p > 65535)
			return -1;

		server_port = (int)p;
		return 0;
	}

	if (strcmp(k, "verbose_log") == 0) {
		bool b;
		if (parse_bool(v, &b) < 0)
			return -1;

		verbose_log = b;
		return 0;
	}

	if (strcmp(k, "cors_origin") == 0) {
		snprintf(cors_origin, sizeof(cors_origin), "%s", v);
		return 0;
	}

	if (strcmp(k, "http_io_timeout") == 0) {
		char* end = NULL;
		long t = strtol(v, &end, 10);
		if (!end || *end != '\0')
			return -1;

		if (t < 1 || t > 300)
			return -1;

		http_io_timeout = (int)t;
		return 0;
	}

	if (strcmp(k, "max_clients") == 0) {
		char* end = NULL;
		long n = strtol(v, &end, 10);
		if (!end || *end != '\0')
			return -1;

		if (n < 1 || n > 1024)
			return -1;

		max_clients = (int)n;
		return 0;
	}

	/* auth */
	if (strcmp(k, "user") == 0) {
		return users_push(v);
	}

	if (strcmp(k, "pass") == 0) {
		return users_set_pass(v);
	}

	if (strcmp(k, "allow") == 0) {
		return users_add_allow(v);
	}

	/* unknown key */
	return 0;
}

static char* trim(char* s)
{
	while (*s && (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n'))
		s++;

	char* e = s + strlen(s);
	while (e > s) {
		char c = e[-1];
		if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
			break;
		e--;
	}
	*e = '\0';
	return s;
}

void config_load(void)
{
	const char* e = getenv("PARADOS_CONFIG");
	const char* path = "";
	if (e && e[0]) {
		(void)load_path(e);
		path = e;
		goto log;
	}

	if (load_path("/etc/parados.conf") == 0) {
		path = "/etc/parados.conf";
		goto log;
	}

	if (load_path("./parados.conf") == 0) {
		path = "./parados.conf";
		goto log;
	}

	LOG(true, "CONF", "Unable to load configuration... using defaults", e);
	return;

log:
	(void)0;

	char port[8];
	char tmo[16];

	LOG(true, "CONF", "Config File        %s", path);
	LOG(true, "CONF", "Media Directory    %s", media_dir);
	LOG(true, "CONF", "Server Address     %s", server_addr);
	snprintf(port, sizeof(port), "%d", server_port);
	LOG(true, "CONF", "Server Port        %s", port);
	LOG(true, "CONF", "Verbose Logging    %s", (verbose_log) ? "true" : "false");
	LOG(true, "CONF", "CORS origins       %s", cors_origin);
	snprintf(tmo, sizeof(tmo), "%d", http_io_timeout);
	LOG(true, "CONF", "HTTP IO Timeout    %s", tmo);

	return;
}

