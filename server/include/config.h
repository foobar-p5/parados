#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

#define VERSION "1.0"

extern char media_dir[4096];
extern char server_addr[64];
extern int server_port;
extern bool verbose_log;
extern char cors_origin[1024];

enum {
	HTTP_REQ_MAX   = 8192,
	HTTP_RESP_MAX  = 2048,
	LISTEN_BACKLOG = 64,
};

void config_load(void);

#endif /* CONFIG_H */

