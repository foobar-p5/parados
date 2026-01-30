#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

extern char media_dir[4096];
extern char server_addr[64];
extern char cors_origin[1024];
extern bool verbose_log;
extern int server_port;
extern int http_io_timeout;

void config_load(void);

#endif /* CONFIG_H */

