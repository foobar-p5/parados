#ifndef LOG_H
#define LOG_H

#include <stdbool.h>

void logmsg(bool verbose, const char* tag, const char* fmt, ...);

#endif /* LOG_H */

