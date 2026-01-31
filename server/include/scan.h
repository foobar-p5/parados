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

/*
	Free all memory owned by a library
		@param  l Library to free
		@return None

	Safe to call multiple times
*/
void scan_library_free(struct library* l);

/*
	Build library by recursively scanning given directory
		@param l     Output library (initialised by function)
		@param root  Media root directory
		@return      0=Success,
		            -1=Failure
*/
int scan_library(struct library* l, const char* root);

/*
	Rescan given directory and replace current library contents
		@param l     Library to replace
		@param root  Media root directory
		@return      0=Success,
		            -1=Failure

	On success, old library contents are freed.
*/
int scan_library_rescan(struct library* l, const char* root);

#endif /* SCAN_H */

