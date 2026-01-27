#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

extern char media_dir[4096];
extern char server_addr[64];
extern int server_port;
extern bool verbose_log;
extern char cors_origin[1024];

enum {
	HTTP_REQ_MAX   = 2048,
	HTTP_RESP_MAX  = 512,
	LISTEN_BACKLOG = 64,
};

void config_load(void);

#endif /* CONFIG_H */

