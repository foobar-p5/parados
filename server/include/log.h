#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#include "config.h"

static inline void log_datetime(char out[20])
{
	time_t t = time(NULL);
	struct tm tmv;

	localtime_r(&t, &tmv);
	strftime(out, 20, "%d/%m/%Y %H:%M:%S", &tmv);
}

static inline void log_vprint(bool verbose, const char* tag,
#if defined(DEBUG)
		const char* file, int line, const char* func,
#endif
		const char* fmt, va_list ap)
{
	if (!verbose)
		return;

	char dt[20];
	log_datetime(dt);
	fprintf(stderr, "%s [%s] ", dt, tag);

#if defined(DEBUG)
	fprintf(stderr, "[%s : %d : %s()] ", file, line, func);
#endif

	vfprintf(stderr, fmt, ap);

	fputc('\n', stderr);
}

static inline void log_print(bool verbose, const char* tag,
#if defined(DEBUG)
		const char* file, int line, const char* func,
#endif
		const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	log_vprint(verbose, tag,
#if defined(DEBUG)
			file, line, func,
#endif
			fmt, ap);

	va_end(ap);
}

#if defined(DEBUG)
#define LOG(verbose_log, tag, fmt, ...) \
	log_print((verbose_log), (tag), __FILE__, __LINE__, __func__, (fmt), ##__VA_ARGS__)
#else
#define LOG(verbose_log, tag, fmt, ...) \
	log_print((verbose_log), (tag), (fmt), ##__VA_ARGS__)
#endif

#endif /* LOG_H */

