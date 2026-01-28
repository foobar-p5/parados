#ifndef USERS_H
#define USERS_H

#include <stdbool.h>
#include <stddef.h>

struct user {
	char           name[64];
	char           pass[128];

	char**         allow;
	size_t         allow_len;
	size_t         allow_cap;
};

struct users {
	struct user*   v;
	size_t         len;
	size_t         cap;
};

extern struct users users;

bool user_allows_path(const struct user* u, const char* relpath);
int users_add_allow(const char* prefix);
const struct user* users_auth_from_hdr(const char* hdr);
void users_free(void);
int users_push(const char* name);
int users_set_pass(const char* pass);

#endif /* USERS_H */

