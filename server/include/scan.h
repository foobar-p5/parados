#ifndef SCAN_H
#define SCAN_H

#include <stddef.h>
#include <stdint.h>

struct item {
	uint64_t       id;
	char*          path;
};

struct library {
	struct item*   items;
	size_t         len;
	size_t         cap;
};

void scan_library_free(struct library* l);
int scan_library(struct library* l, const char* root);
int scan_library_rescan(struct library* l, const char* root);

#endif /* SCAN_H */

