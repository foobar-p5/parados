#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>

const char* cistrstr(const char* hay, const char* nee);
int hdr_get_value(char out[512], const char* hdr, const char* key);
int join_path(char* out, size_t outsz, const char* a, const char* b);
int write_all(int fd, const void* buf, size_t n);

#endif /* UTIL_H */

