#ifndef DARRAY_H_
#define DARRAY_H_

#include <stdlib.h>
#include <assert.h>
#include <sys/mman.h>
#include <string.h> /* strlen(), memcpy() */
#include <fcntl.h>	/* open() */
#include <unistd.h>	/* close() */
#include <sys/stat.h> /* struct stat, stat() */

struct darray;

enum VALUE_TYPE {UNSIGNED_INT, BITSET};

int darray_init(struct darray *d, const enum VALUE_TYPE val_type,
		const size_t init_size, const size_t val_size,
		const char *dir, const char *name, const char *ext);

void darray_free(struct darray *d);

#endif
