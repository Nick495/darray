#ifndef DARRAY_H_
#define DARRAY_H_

#include <stdlib.h>
#include <assert.h>
#include <sys/mman.h>
#include <string.h> /* strlen(), memcpy() */
#include <fcntl.h>	/* open() */
#include <unistd.h>	/* close() */
#include <sys/stat.h> /* struct stat, stat() */
#include <errno.h>	/* errno */
#include "darray_xmacro.h" /* DARRAY_ERROR, darray_strerror() */

struct darray;

enum VALUE_TYPE {UNSIGNED_INT, BITSET};

enum DARRAY_ERROR darray_init(struct darray *d, const size_t val_cnt, 
		enum VALUE_TYPE *val_type, size_t *val_size,
		const char *dir, const char *name, const char *ext);

enum DARRAY_ERROR darray_free(struct darray *d);

#endif
