#ifndef JSON_H
#define JSON_H

#include <stddef.h>
#include <stdint.h>

#include "scan.h"

struct json {
	char*          buf;
	size_t         len;
	size_t         cap;
};

void json_free(struct json* j);
int json_library(struct json* j, const struct library* l);

#endif /* JSON_H */

