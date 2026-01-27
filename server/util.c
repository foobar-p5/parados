#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

const char* cistrstr(const char* hay, const char* nee)
{
	size_t nl = strlen(nee);
	if (nl == 0)
		return hay;

	for (; *hay; hay++) {
		size_t i = 0;

		for (;;) {
			if (i == nl)
				return hay;

			unsigned char a = (unsigned char)hay[i];
			unsigned char b = (unsigned char)nee[i];

			if (a == '\0')
				break;

			if (tolower(a) != tolower(b))
				break;

			i++;
		}
	}

	return NULL;
}

int hdr_get_value(char out[512], const char* hdr, const char* key)
{
	char pat1[64];
	char pat2[64];
	char pat3[64];

	/* build patterns like "\nXXXX:" "\rXXXX:" "XXXX:" */
	if (snprintf(pat1, sizeof(pat1), "\n%s:", key) >= (int)sizeof(pat1))
		return -1;
	if (snprintf(pat2, sizeof(pat2), "\r%s:", key) >= (int)sizeof(pat2))
		return -1;
	if (snprintf(pat3, sizeof(pat3), "%s:", key) >= (int)sizeof(pat3))
		return -1;

	const char* p = cistrstr(hdr, pat1);
	if (!p)
		p = cistrstr(hdr, pat2);
	if (!p)
		p = cistrstr(hdr, pat3);
	if (!p)
		return -1;

	p = strchr(p, ':');
	if (!p)
		return -1;
	p++;

	while (*p == ' ' || *p == '\t')
		p++;

	size_t n = 0;
	while (*p && *p != '\r' && *p != '\n') {
		if (n + 1 >= 512)
			return -1;
		out[n++] = *p++;
	}
	out[n] = '\0';

	if (n == 0)
		return -1;

	return 0;
}

int join_path(char* out, size_t outsz, const char* a, const char* b)
{
	int n = snprintf(out, outsz, "%s/%s", a, b);
	if (n < 0)
		return -1;

	if ((size_t)n >= outsz)
		return -1;

	return 0;
}

int write_all(int fd, const void* buf, size_t n)
{
	const char* p = buf;

	while (n > 0) {
		ssize_t w = write(fd, p, n);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		p += (size_t)w;
		n -= (size_t)w;
	}

	return 0;
}

