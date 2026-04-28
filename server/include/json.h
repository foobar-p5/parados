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

/**
 * @brief Free memory owned by JSON buffer
 *
 * @note Safe to call on NULL or already freed buffers
 *
 * @param j JSON object to free
 */
void json_free(struct json* j);

/**
 * @brief Encode library to JSON
 *
 * @note On failure, j is freed/emptied
 *
 * @param j Output JSON buffer (initialised by in function)
 * @param l Input library
 *
 * @return 0=Success, -1=Failure
 */
int json_library(struct json* j, const struct library* l);

/**
 * @brief Encode item metadata to JSON
 *
 * @note On failure, j is freed/emptied
 *
 * @param j Output JSON buffer (initialised by this function)
 * @param it Item (id + relative path)
 * @param size File size in bytes
 * @param mtime File modification time in epoch seconds
 * @param type MIME type string
 *
 * @return 0=Success, -1=Failure
 */
int json_meta(struct json* j, const struct item* it, size_t size, long mtime, const char* type);

#endif /* JSON_H */

