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

/**
 * @brief Check whether relpath is permitted for a given user.
 *
 * @param u User entry.
 * @param relpath Path relative to media_dir.
 *
 * @return true=permitted, false=not-permitted
 */
bool user_allows_path(const struct user* u, const char* relpath);

/**
 * @brief Add an allow prefix to the most recently pushed user
 *
 * @param prefix Allowed prefix (e.g. "Music/", "TV/", "*")
 *
 * @return 0=Success, -1=Failure
 */
int users_add_allow(const char* prefix);

/**
 * @brief Authenticate request using the "Authorization" header.
 *
 * @note Returns NULL if authentication is disabled
 *
 * @param hdr Full HTTP request header buffer.
 *
 * @return User Ptr=Success, NULL=Failure.
 */
const struct user* users_auth_from_hdr(const char* hdr);

/**
 * @brief Free all memory owned by the global user table.
 */
void users_free(void);

/**
 * @brief Create new user entry and append it to the global users table
 *
 * @param name Username
 *
 * @return 0=Success, -1=Failure
 */
int users_push(const char* name);

/**
 * @brief Set the password for most recently pushed user
 *
 * @note Empty password creates a passwordless user
 *
 * @param pass Password string
 *
 * @return 0=Success, -1=Failure
 */
int users_set_pass(const char* pass);

#endif /* USERS_H */

