#include <stdbool.h>

static const char*  media_dir     = "/path/to/media";
static const char*  server_addr   = "127.0.0.1";
static const int    server_port   = 3579;
static const bool   verbose_log   = false;

enum {
	HTTP_REQ_MAX   = 2048,
	HTTP_RESP_MAX  = 512,
	LISTEN_BACKLOG = 64,
};

