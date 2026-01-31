#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

extern char media_dir[4096];
extern char server_addr[64];
extern char cors_origin[1024];
extern bool verbose_log;
extern int server_port;
extern int http_io_timeout;
extern int max_clients;

/*
	Load configuration and populate global settings
	in the order:
		1) $PARADOS_CONFIG
		2) /etc/parados.conf
		3) ./parados.conf

		@param  None
		@return None

	If no config is available, defaults are used
*/
void config_load(void);

#endif /* CONFIG_H */

