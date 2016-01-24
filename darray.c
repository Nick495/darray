#include "darray.h"
#include <stdio.h> /* DEBUG: */

/*
 * Note: There is doubtlessly some expense to the serialization and
 * deserialization every access. in my testing, I've only managed to see a
 * .6% difference on a late-2013 i7 macbook pro. Therefore, I'm leaving it in.
 *
 * Note 2: I've found a 5% performance advantage (averaged over 3 runs each)
 * on my setup for mmap() as compared to malloc(). The only justification I can
 * manage for this phenomon is that malloc() is using mmap() as it's back end
 * for large allocations, and therefore the 5% represents the locking and
 * other overhead associated with malloc() itself.
 *
 * TODO: Find a way to pretty-up the polymorphism here?
 *	Specifically darray_*_push(), darray_*_get(), as well as the switch()
 *	in darray_init().
 *	Also find a way to pretty-up the SERIAL vs NOSERIAL code.
 *	#define is ugly.
 *
 * TODO: Double check with someone else that bitarray is being used properly
 *
 * TODO: There is something really, really wrong with the init and alloc code.
 * bit arrays never extend, and unsigned ints blow up. check the darray_init()
 * section where we select the type and try to fix it, yeah?
*/

#define HEADER_IDENTIFIER 0xDEADBEEFCAFED00D
#define HEADER_VERSION 0
#define HEADER_LENGTH 6*sizeof(uint64_t)

/* Only for function prototypes and structs so they'll fit in 80-columns. */
typedef enum DARRAY_ERROR de;

struct darray {
	uint64_t use;
	uint64_t cap;
	/* items below this point are not saved persistently,
	 * they're recreated by init().
	*/
	size_t lsize; /* Literal size of the backend. */
	char *path;
	unsigned char *data;
	de (*push)(struct darray *, const void *);
	void (*get)(const struct darray *, const size_t, void *);
};

static de darray_uint8_push(struct darray *, const void *);
static void darray_uint8_get(const struct darray *, const size_t, void *);
static de darray_uint16_push(struct darray *, const void *);
static void darray_uint16_get(const struct darray *,const size_t, void *);
static de darray_uint32_push(struct darray *, const void *);
static void darray_uint32_get(const struct darray *d,const size_t, void *);
static de darray_uint64_push(struct darray *, const void *);
static void darray_uint64_get(const struct darray *d,const size_t, void *);
static de darray_bset_push(struct darray *, const void *);
static void darray_bset_get(const struct darray *, const size_t, void *);

#ifndef MALLOC
/*
 * This function attempts to stretch the file located at 'path' to the size
 * specified by 'new_size' and puts the resultant file descriptor into the
 * location that fd points to.
 *
 * Requires that path and fd are not null, and that new_size is > 0.
 *
 * Returns SUCCESS on success.
*/
static enum DARRAY_ERROR
stretch_size(const char *path, int *fd, const size_t new_size)
{
	/* Preconditions */
	assert(path != NULL);
	assert(fd != NULL);
	assert(new_size > 0);

	enum DARRAY_ERROR rc = SUCCESS;
	const int fd_local = open(path, O_RDWR|O_CREAT|O_NOFOLLOW);
	if (fd_local < 0) {
		rc = D_OPEN;
		goto fail_open;
	}

	if (lseek(fd_local, new_size, SEEK_SET) == -1) {
		rc = D_LSEEK;
		goto fail_lseek;
	}

	if (write(fd_local, "", 1) == -1) {
		rc = D_WRITE;
		goto fail_write;
	}

	*fd = fd_local;
	/* Postconditions */
	assert(fd != NULL);
	assert(*fd > 0);
	assert(rc == SUCCESS);
	return SUCCESS;

fail_write:
fail_lseek:
	close(fd_local);
fail_open:
	fd_local = -1;
	*fd = -1;
	assert(fd != NULL);
	assert(*fd == -1);
	assert(fd_local == -1);
	assert(rc != SUCCESS);
	return rc;
}

/*
 * This function attempts to allocate a memory-map to the file located at
 * d->path with at least new_size bytes of space. If new_size is zero, then
 * the function will attempt to memory map the entire file at d->path.
 * (This functionality is used for persistent recovery).
 *
 * Requires that d and d->path are not null.
 *
 * Returns either SUCCESS or EMPTY_FILE if the file doesn't exist, on success.
*/
static enum DARRAY_ERROR
darray_alloc_mmap(struct darray *d, size_t new_size)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->path != NULL);

	enum DARRAY_ERROR rc = SUCCESS;

	struct stat statb;
	if ((rc = stat(d->path, &statb))) {
		switch (errno) {
		default:
			rc = D_STAT;
			goto fail_stat;
		case ENOENT:
			/* Open will create it anyway. */
			statb.st_size = 0;
			break;
		}
	}

	int fd = -1;
	if ((new_size == 0) && (statb.st_size == 0)) {
		/* Postconditions */
		assert(d != NULL);
		assert(d-> path != NULL);
		/* Not an error condition, so we don't jump to fail_* */
		return EMPTY_FILE;
	}

	if (new_size <= (size_t)statb.st_size) {
		if ((fd = open(d->path, O_RDWR|O_NOFOLLOW)) < 0) {
			rc = D_OPEN;
			goto fail_open;
		}
		/* WARNING: for optimal (and, as the back-end grows larger,
		 * reasonable, file size usage, this line assumes that this
		 * program (or some version thereof) is the only thing which
		 * can extend the back-end'sfile size. This is due to the below
		 * line, which otherwise would have to be made a special case
		 * for new_size == 0 and creates ugly code.
		*/
		new_size = statb.st_size;
	} else {
		/* Extend the file as needed */
		if ((rc = stretch_size(d->path, &fd, new_size)) != SUCCESS) {
			goto fail_extend_file;
		}
	}
	assert(fd > 0);

	void *new_data = mmap(0, new_size,
	    PROT_READ|PROT_WRITE, MAP_FILE|MAP_SHARED, fd, 0);
	if (!new_data) {
		rc = D_MMAP;
		goto fail_mmap;
	}
	assert(new_data != NULL);

	/* It seems like all the errors are usage or signal interruption.
	 * Maybe I should try closing() in a loop to avoid a signal killing the
	 * close? TODO.
	*/
	if (close(fd) == -1) {
		rc = D_CLOSE;
		goto fail_close;
	}
	fd = -1;

	d->data = new_data;
	d->lsize = new_size;

	/* Postconditions */
	assert(d != NULL);
	assert(d->path != NULL);
	assert(d->data != NULL);
	assert(fd == -1);
	assert(d->lsize >= new_size);
	assert(rc == SUCCESS);
	return SUCCESS;

fail_close:
	assert(munmap(new_data, new_size) == 0); /* All errors usage. */
fail_mmap:
	close(fd);
fail_open:
fail_extend_file:
fail_stat:
	assert(rc != SUCCESS && rc != EMPTY_FILE);
	return rc;
}

#else

/*
 * This function attempts to allocate a buffer with at least new_size bytes of
 * space.
 *
 * Requires that d is not null and new_size is greater than zero.
 *
 * Returns SUCCESS on success.
*/
static enum DARRAY_ERROR
darray_alloc_malloc(struct darray *d, size_t new_size)
{
	/* Preconditions */
	assert(d != NULL);
	assert(new_size > 0);

	enum DARRAY_ERROR rc;
	void *new_data = realloc(d->data, new_size);
	if (!new_data) {
		rc = D_MALLOC;
		goto fail_realloc;
	}
	assert(new_data != NULL);

	d->data = new_data;
	d->lsize = new_size;

	/* Postconditions */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(d->lsize >= new_size);
	return 0;

	free(new_data);
fail_realloc:
	assert(rc != SUCCESS && rc != EMPTY_FILE);
	return rc;
}

#endif

/*
 * This function attempts to change the backend of the given darray (malloc()
 * or mmap()) to the new_size.
 * See darray_alloc_mmap() and darray_alloc_malloc() for more detail.
 *
 * Requires that d and d->path are not null.
*/
static enum DARRAY_ERROR
darray_alloc(struct darray *d, size_t new_size)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->path != NULL);

	enum DARRAY_ERROR rc;
#ifndef MALLOC
	rc = darray_alloc_mmap(d, new_size);
#else
	rc = darray_alloc_malloc(d, new_size);
#endif

	/* Postconditions */
	if (rc == SUCCESS) {
		assert(d->data != NULL);
	}
	return rc;
}

#ifndef MALLOC
/*
 * This function serializes the uint64_t given by val and puts it into str.
 *
 * Requires that str is not null, and assumes that str has space for val.
 *
 * Returns the number of bytes of str consumed.
*/
static size_t
uint64_serialize(const uint64_t val, unsigned char *str)
{
	assert(str != NULL);

	str[0] = (val >> 56);
	str[1] = (val >> 48);
	str[2] = (val >> 40);
	str[3] = (val >> 32);
	str[4] = (val >> 24);
	str[5] = (val >> 16);
	str[6] = (val >> 8);
	str[7] = (val >> 0);

	return sizeof(uint64_t);
}

/*
 * This function deserializes the string pointed to by str and returns its
 * value.
 *
 * Requires that str is not null and assumes that str has a val to be recovered
*/
static uint64_t
uint64_deserialize(const unsigned char *str)
{
	assert(str != NULL);
	return ((uint64_t)str[0] << 56) | ((uint64_t)str[1] << 48) |
		((uint64_t)str[2] << 40) | ((uint64_t)str[3] << 32) |
		((uint64_t)str[4] << 24) | ((uint64_t)str[5] << 16) |
		((uint64_t)str[6] << 8) | ((uint64_t)str[7] << 0);
}

/*
 * This function serializes the enum VALUE_TYPE given by 'vt' into str.
 * Like the above functions, it assumes that str is not null and that it has
 * space for 'vt'.
 *
 * Returns the amount of space of str consumed by vt.
*/
static size_t
value_type_serialize(const enum VALUE_TYPE vt, unsigned char *str)
{
	assert(str != NULL);

	switch(vt) {
	case UNSIGNED_INT:
		return uint64_serialize(0, str);
		break;
	case BITSET:
		return uint64_serialize(1, str);
		break;
	}
}

/*
 * This function deserializes an enum VALUE_TYPE in 'str' and compares it to
 * the one pointed to by 'v'.
 *
 * Requires that v and str are not null.
 *
 * Returns SUCCESS on SUCCESS, D_MISMATCH_TYPE if the two enums do not match,
 * and an error code otherwise.
*/
static enum DARRAY_ERROR
value_type_deserialize(const unsigned char *str, enum VALUE_TYPE *v)
{
	assert(str != NULL);
	assert(v != NULL);

	enum DARRAY_ERROR rc = SUCCESS;
	enum VALUE_TYPE raw_vt;

	const uint64_t deserial_value = uint64_deserialize(str);
	switch(deserial_value) {
	case 0:
		raw_vt = UNSIGNED_INT;
		break;
	case 1:
		raw_vt = BITSET;
		break;
	default:
		rc = D_BAD_TYPE;
		goto fail_value_type;
	}

	if (raw_vt != *v) {
		rc = D_MISMATCH_TYPE;
		goto fail_mismatch_type;
	}

	assert(rc == SUCCESS);
	return SUCCESS;

fail_mismatch_type:
fail_value_type:
	assert(rc != SUCCESS);
	return rc;
}

/*
 * This function serializes the darray header into d->data.
 *
 * Requires that d and d->data are not NULL. It also requires that value_size
 * is greater than zero.
 *
 * Returns SUCCESS on success and an error code otherwise.
*/
static void
darray_header_serialize(struct darray *d, const enum VALUE_TYPE valtyp,
	const size_t value_size)
{
	/* Preconditions. */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(d->use <= d->cap);
	assert(value_size > 0);

	/* Header format is IDENTIFIER | VERSION | TYPE | SIZE | USE | CAP */
	uint64_serialize((uint64_t)HEADER_IDENTIFIER,
	    d->data + 0 * sizeof(uint64_t));
	uint64_serialize((uint64_t)HEADER_VERSION,
	    d->data + 1 * sizeof(uint64_t));
	value_type_serialize(valtyp,
	    d->data + 2 * sizeof(uint64_t));
	uint64_serialize((uint64_t)value_size,
	    d->data + 3 * sizeof(uint64_t));
	uint64_serialize((uint64_t)d->use,
	    d->data + 4 * sizeof(uint64_t));
	uint64_serialize((uint64_t)d->cap,
	    d->data + 5 * sizeof(uint64_t));

	return;
}

static void
darray_header_update(struct darray *d)
{
	/* Preconditions. */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(d->use <= d->cap);

	printf("DEBUG d->use: %llu\nDEBUG d->cap: %llu\n", d->use, d->cap);
	/* Header format is IDENTIFIER | VERSION | TYPE | SIZE | USE | CAP */
	/* As long as use and cap are the last two elements, this will work. */
#if 0
	uint64_serialize((uint64_t)d->use,
	    d->data + HEADER_LENGTH - 2 * sizeof(uint64_t));
	uint64_serialize((uint64_t)d->cap,
	    d->data + HEADER_LENGTH - 1 * sizeof(uint64_t));
#endif
	uint64_serialize((uint64_t)d->use,
	    d->data + 4 * sizeof(uint64_t));
	uint64_serialize((uint64_t)d->cap,
	    d->data + 5 * sizeof(uint64_t));

}

/*
 * This function deserializes a darray_header from d->data, and sets parameters
 * as it can. It also compares these deserialized parameters to those supplied
 * by the caller, and emits an error code if they mismatch.
 *
 * Requires that all parameters, and d->data are not NULL.
 *
 * Returns SUCCESS on success, a mismatch code as described above, and an error
 * code otherwise.
*/
static enum DARRAY_ERROR
darray_header_deserialize(struct darray *d, enum VALUE_TYPE *val_type,
		size_t *val_size)
{
	/* Preconditions. */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(val_type != NULL);
	assert(val_size != NULL);
	assert(*val_size > 0);

	enum DARRAY_ERROR rc = SUCCESS;

	/* Attempt to deserialize the struct from the file. */
	if (uint64_deserialize(d->data + 0 * sizeof(uint64_t))
	    != (uint64_t)HEADER_IDENTIFIER) {
		/* Bad file identifier. */
		rc = D_BAD_IDENTIFIER;
		goto fail_file;
	}

	if (uint64_deserialize(d->data + 1 * sizeof(uint64_t))
	    > HEADER_VERSION) {
		/* We can't read files of this version. */
		rc = D_BAD_VERSION;
		goto fail_version;
	}

	/* Ensure that the type is as we expect. */
	if ((rc = value_type_deserialize(d->data + 2 * sizeof(uint64_t),
	    val_type)) != SUCCESS) {
		goto fail_value_type_deserialize;
	}


	const uint64_t persisted_vsize =
		uint64_deserialize(d->data + 3 * sizeof(uint64_t));
	printf("DEBUG deserialize: %llu\n", persisted_vsize);

	/* Value_size is arbitrary for bitsets. */
	if ((*val_type != BITSET) && (persisted_vsize != *val_size)){
		rc = D_MISMATCH_VALUE_SIZE;
		printf("DEBUG 1: %zu\n", *val_size);
		*val_size = persisted_vsize;
		printf("DEBUG 2: %zu\n", *val_size);
		goto fail_mismatch_size;
	}

	d->use = uint64_deserialize(d->data + 4 * sizeof(uint64_t));
	d->cap = uint64_deserialize(d->data + 5 * sizeof(uint64_t));
	printf("DEBUG deserialize d->use: %llu\n", d->use);
	printf("DEBUG deserialize d->cap: %llu\n", d->cap);
	if (d->cap < d->use) {
		rc = D_BAD_USECAP;
		goto fail_usecap;
	}

	assert(rc == SUCCESS);
	return SUCCESS;

fail_usecap:
fail_mismatch_size:
fail_value_type_deserialize:
fail_version:
fail_file:
	assert(rc != SUCCESS);
	return rc;
}

/*
 * This function attempts to restore a darray from the file pointed to by
 * d->path. It reports if the file doesn't exist. It also compares the
 * VALUE_TYPE and val_size fields to those supplied by the user, and emits an
 * error code if they mismatch.
 *
 * Requires that all parameters, and d->path are not null.
 *
 * Returns SUCCESS or EMPTY_FILE on success, a mismatch code as described
 * above, and an error code otherwise.
*/
static enum DARRAY_ERROR
darray_attempt_restore(struct darray *d, enum VALUE_TYPE *val_type,
		size_t *val_size)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->path != NULL);
	assert(val_type != NULL);
	assert(val_size != NULL);

	enum DARRAY_ERROR rc;

	rc = darray_alloc(d, 0); /* Have darray_alloc() map the whole file. */

	switch(rc) {
	default: /* Error in darray_alloc */
		goto fail_darray_alloc_persistance;
	case EMPTY_FILE:
		assert(d->data == NULL);
		return EMPTY_FILE; /* Not a failure case. */
	case SUCCESS:  /* The file has stuff. Continue. */
		break;
	}

	assert(d->data != NULL);

	if ((rc = darray_header_deserialize(d, val_type, val_size))
			!= SUCCESS) {
		goto fail_darray_header_deserialize;
	}

	/* Postconditions */
	assert(d != NULL);
	assert(d->cap >= d->use);
	assert(d->data != NULL);
	assert(d->path != NULL);
	assert(d->lsize > 0);
	if (*val_type != BITSET) {
		assert(d->lsize > d->cap);
	}
	return SUCCESS;

fail_darray_header_deserialize:
	munmap(d->data, d->lsize);
	d->data = NULL;
fail_darray_alloc_persistance:
	/* Post conditions */
	assert(d != NULL);
	assert(d->data == NULL);
	assert(d->path != NULL);
	assert(rc != SUCCESS);
	return rc;
}
#endif

/*
 * This function ensures that there is room for another element in the given
 * darray's backend, and atttemps to expand it otherwise.
 *
 * Returns SUCCESS on success.
*/
static enum DARRAY_ERROR
darray_ensure_size(struct darray *d)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->use <= d->cap);
	assert(d->data != NULL);

	const size_t dbg_size = d->lsize;

	enum DARRAY_ERROR rc;
	if (d->use < d->cap) { /* Early exit, since we have no work to do. */
		/* Postconditions */
		assert(d != NULL);
		assert(d->use < d->cap);
		assert(d->data != NULL);
		return SUCCESS;
	}

	/*Otherwise extend the size of the array to make room for the insert.*/
	const int expn_factor = 2; /* Replace as needed. */
	const size_t new_size = d->lsize * expn_factor;
	const size_t new_cap = d->cap * expn_factor;
	if ((new_size < d->lsize) || (new_cap < d->cap)) {
		rc = D_WRAP;
		goto fail_uint_wrap;
	}
	assert(new_size > d->lsize);
	assert(new_cap > d->cap);

	printf("DEBUG lsize: %zu | d->cap %llu\n", d->lsize, d->cap);
	if ((rc = darray_alloc(d, new_size))) {
		goto fail_darray_alloc;
	}
	printf("DEBUG lsize: %zu | d->cap %llu\n", d->lsize, d->cap);
	assert(d->data != NULL);

	d->cap = new_cap;

	/* Post_conditions. */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(d->lsize > dbg_size);
	assert(d->use <= d->cap);
	return 0;

fail_darray_alloc:
fail_uint_wrap:
	assert(rc != SUCCESS);
	return rc;
}

/* This function allocates memory for the path 'dir/name.ext'
 *
 * It requires that path points to NULL, and that dir, name, and ext are not
 * null pointers.
 *
 * Returns SUCCESS on SUCCESS, and an error code other wise.
*/
static enum DARRAY_ERROR
create_path(char **path, const char *dir, const char *name, const char *ext)
{
	assert(*path == NULL);
	assert(dir != NULL);
	assert(name != NULL);
	assert(ext != NULL);

	size_t dir_len = strlen(dir);
	size_t name_len = strlen(name);
	size_t ext_len = strlen(ext);

	enum DARRAY_ERROR rc;
	/* Additional space for a slash, a period, and a null terminator. */
	*path = malloc(dir_len + name_len + ext_len + 3);
	if (*path == NULL) {
		rc = D_MALLOC;
		goto fail_malloc;
	}

	assert(*path != NULL);

	/* Copy over appropriate fields, with unix path conventions. */
	memcpy(*path, dir, dir_len);
	(*path)[dir_len] = '/';
	memcpy(*path + dir_len + 1, name, name_len);
	(*path)[dir_len + name_len + 1] = '.';
	memcpy(*path + dir_len + name_len + 2, ext, ext_len + 1);/* null too */

	/* Postconditions. */
	assert((*path)[dir_len + name_len + ext_len + 2] == '\0');
	return SUCCESS;

fail_malloc:
	*path = NULL;

	assert(rc != SUCCESS);
	assert(*path == NULL);
	return rc;
}

/*
 * Initializes a struct darray, restoring it from a previous location located
 * at the path 'dir/name.ext' if it exists. If that previous location holds a
 * struct darray with a different type or size, this function will alert with
 * a code. It will do likewise if the location is being used for another file.
 *
 * It requires that each pointer argument is non-null, and that val_cnt and the
 * value pointed to by val_size are greater than zero.
 *
 * Returns SUCCESS on SUCCESS, an error code otherwise.
*/
enum DARRAY_ERROR
darray_init(struct darray *d, const size_t val_cnt, enum VALUE_TYPE *val_type,
	size_t *val_size, const char *dir, const char *name, const char *ext)
{
	/* Preconditions */
	assert(d != NULL);
	assert(val_type != NULL);
	assert(val_size != NULL);
	assert(val_cnt >= 0);
	assert(*val_size > 0);
	assert(dir != NULL);
	assert(name != NULL);
	assert(ext != NULL);

	enum DARRAY_ERROR rc;

	d->use = d->cap = d->lsize = 0;
	d->data = NULL;
	d->path = NULL;
	if ((rc = create_path(&d->path, dir, name, ext)) != SUCCESS) {
		goto fail_path_malloc;
	}

	assert(d->path != NULL);

#ifndef MALLOC
	/* Initialize the rest of the darray struct, using a persistent version
	 * stored on the file if it exists.
	*/
	rc = darray_attempt_restore(d, val_type, val_size);
#else
	rc = EMPTY_FILE; /* Malloc isn't persistent. */
#endif

	switch(rc) {
	case SUCCESS:
		break;
	default:
		goto fail_darray_attempt_restore;
	case EMPTY_FILE: /* Init the darray since the file can't. */
		d->use = 0;
		d->cap = (val_cnt == 0) ? 5 : val_cnt;
		d->lsize = 0;
		d->data = NULL;
		d->push = NULL;
		d->get = NULL;
		break;
	}

	/* Lame polymorphism */
	size_t alloc_size = 0;
	switch(*val_type) {
	case UNSIGNED_INT: {
		switch(*val_size) {
		case sizeof(uint8_t):
			d->push = darray_uint8_push;
			d->get = darray_uint8_get;
			break;
		case sizeof(uint16_t):
			d->push = darray_uint16_push;
			d->get = darray_uint16_get;
			break;
		case sizeof(uint32_t):
			d->push = darray_uint32_push;
			d->get = darray_uint32_get;
			break;
		case sizeof(uint64_t):
			d->push = darray_uint64_push;
			d->get = darray_uint64_get;
			break;
		default:
			break;
		}

		alloc_size = d->cap * *val_size;
		if (alloc_size < d->cap) {
			rc = D_WRAP;
			goto fail_lsize_wrap;
		}
		assert(alloc_size >= d->cap);
		break;
	}
	case BITSET: {
		d->push = darray_bset_push;
		d->get = darray_bset_get;
		/* Note, we reserve space for the largest possible integer
		 * (uint64_t) so that no matter what architecture we're working
		 * on, it will be able to operate at its native word size for
		 * maximum efficiency. (Bitsets are endian independent, so the
		 * only portability issue is word size). (Otherwise, we might
		 * run into issues with an array allocated on an arch with a
		 * small worlsize (e.g. 16 bits) on an arch with a bigger word
		 * size (e.g. 32 or 64 bit).
		 *
		 * This function below gives us the rounded up count of uint64s
		 * needed given our val_cnt.
		*/
		alloc_size = (sizeof(uint64_t)-1 + d->cap / sizeof(uint64_t));
		break;
	}
	}

	assert(d->push != NULL);
	assert(d->get != NULL);
	assert(alloc_size > 0);

	if (alloc_size + HEADER_LENGTH < alloc_size) {
		rc = D_WRAP;
		goto fail_alloc_size_wrap;
	}
	alloc_size += HEADER_LENGTH;

	if ((!d->data) && (rc = darray_alloc(d, alloc_size))) {
		/* Failed init. Short circuiting ensures no double-alloc. */
		goto fail_darray_alloc;
	}
	assert(d->data != NULL);
	d->lsize = alloc_size;

	/* Serialize the initial fields of the header for persistance. */
#ifndef MALLOC
	darray_header_serialize(d, *val_type, *val_size);
#endif

	/* Post-conditions */
	assert(d->cap != 0);
	assert(d->use <= d->cap);
	assert(d->data != NULL);
	assert(d->path != NULL);
	assert(d->push != NULL);
	assert(d->get != NULL);
	assert(rc == SUCCESS);
	return rc;

fail_alloc_size_wrap:
fail_darray_alloc:
fail_darray_attempt_restore:
fail_lsize_wrap:
fail_path_malloc:
	darray_free(d);

	/* Post conditions */
	assert(d->data == NULL);
	assert(d->path == NULL);
	assert(rc != SUCCESS);
	return rc;
}

/*
 * Attempts to deallocate a darray pointed to by d.
 *
 * Requires that d is not null.
 *
 * Returns SUCCESS on success.
*/
enum DARRAY_ERROR
darray_free(struct darray *d)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->use <= d->cap);

	if (d->path) {
		free(d->path);
	}
	if (d->data) {
#ifndef MALLOC
		darray_header_update(d);
		if (msync(d->data, d->lsize, MS_SYNC)) {
			switch(errno) {
			/* I have TODO more research into EIO, which is the
			 * only non-usage error I see in my documentation, but
			 * otherwise I don't think I can do much.
			*/
			default:
				break;
			}
		}
		/* assert() is fine because all errors are usage. */
		assert(munmap(d->data, d->lsize) == 0);
#else
		free(d->data);
#endif
	}
	d->use = d->cap = d->lsize = 0;
	d->data = NULL;
	d->path = NULL;

	/* Post conditions */
	assert(d->path == NULL);
	assert(d->data == NULL);
	assert(d->use == 0);
	assert(d->cap == 0);
	assert(d->lsize == 0);
	assert(d->use <= d->cap);
	return SUCCESS;
}

/*
 * This family of functions attempt to append their respective values to the
 * darray.
 *
 * They require that d and v, as well as d->data are not null.
 *
 * They return SUCCESS on success, and an error code otherwise.
*/
static enum DARRAY_ERROR
darray_uint8_push(struct darray *d, const void *v)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(v != NULL);

	assert(d->use <= d->cap);
	assert(d->lsize >= d->cap);

	enum DARRAY_ERROR rc;
	if ((rc = darray_ensure_size(d))) {
		goto fail_darray_ensure_size;
	}
	assert(d->use < d->cap);

	const size_t rind = d->use++ * sizeof(uint8_t);
	assert(rind >= d->use - 1);
	unsigned char *rdata = d->data + HEADER_LENGTH;
#if NOSERIAL
	memcpy(&rdata[rind], v, sizeof(uint8_t));
#else
	rdata[rind] = (*((const uint8_t *) v) >> 0);
#endif
	return SUCCESS;

fail_darray_ensure_size:
	assert(rc != SUCCESS);
	return rc;
}

/*
 * This family of functions attempt to get the value at the given position from
 * the darray and put them into 'v'.
 *
 * They require that d and v, as well as d->data are not null. They also
 * require that the index be valid, that is positive and less than the number
 * of allocated elements in the array.
 *
 * They return SUCCESS on success, and an error code otherwise.
*/
static void
darray_uint8_get(const struct darray *d, const size_t ind, void *v)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(v != NULL);
	assert(ind >= 0);

	assert(d->use <= d->cap);
	assert(ind <= d->use);
	assert(d->lsize >= d->cap);

	const size_t rind = ind * sizeof(uint8_t);
	const unsigned char *rdata = d->data + HEADER_LENGTH;
	assert(rind >= ind);
#if NOSERIAL
	memcpy(v, &rdata[rind], sizeof(uint8_t));
#else
	*((uint8_t *)v) = ((uint8_t)rdata[rind] << 0);
#endif
	return;
}

static enum DARRAY_ERROR
darray_uint16_push(struct darray *d, const void *v)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(v != NULL);

	assert(d->use <= d->cap);
	assert(d->lsize >= d->cap);

	enum DARRAY_ERROR rc;
	if ((rc = darray_ensure_size(d))) {
		goto fail_darray_ensure_size;
	}
	assert(d->use < d->cap);

	const size_t rind = d->use++ * sizeof(uint16_t);
	unsigned char *rdata = d->data + HEADER_LENGTH;
	assert(rind >= d->use - 1);
#if NOSERIAL
	memcpy(&rdata[rind], v, sizeof(uint16_t));
#else
	rdata[rind] = (*((const uint16_t *) v) >> 8);
	rdata[rind + 1] = (*((const uint16_t *) v) >> 0);
#endif
	return SUCCESS;

fail_darray_ensure_size:
	assert(rc != SUCCESS);
	return rc;
}

static void
darray_uint16_get(const struct darray *d, const size_t ind, void *v)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(v != NULL);
	assert(ind >= 0);

	assert(d->use <= d->cap);
	assert(ind <= d->use);
	assert(d->lsize >= d->cap);

	const size_t rind = ind * sizeof(uint16_t);
	const unsigned char *rdata = d->data + HEADER_LENGTH;
#if NOSERIAL
	memcpy(v, &rdata[rind], sizeof(uint16_t));
#else
	*((uint16_t *)v) =
		(((uint16_t)rdata[rind] << 8) | ((uint16_t)rdata[rind + 1] << 0));
#endif
	return;
}

static enum DARRAY_ERROR
darray_uint32_push(struct darray *d, const void *v)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(v != NULL);

	assert(d->use <= d->cap);
	assert(d->lsize >= d->cap);

	enum DARRAY_ERROR rc;
	if ((rc = darray_ensure_size(d))) {
		goto fail_darray_ensure_size;
	}
	assert(d->use < d->cap);

	const size_t rind = d->use++ * sizeof(uint32_t);
	unsigned char *rdata = d->data + HEADER_LENGTH;
	assert(rind >= d->use - 1);
#if NOSERIAL
	memcpy(&rdata[rind], v, sizeof(uint32_t));
#else
	rdata[rind] = (*((const uint32_t *) v) >> 24);
	rdata[rind + 1] = (*((const uint32_t *) v) >> 16);
	rdata[rind + 2] = (*((const uint32_t *) v) >> 8);
	rdata[rind + 3] = (*((const uint32_t *) v) >> 0);
#endif
	return SUCCESS;

fail_darray_ensure_size:
	assert(rc != SUCCESS);
	return rc;
}

static void
darray_uint32_get(const struct darray *d, const size_t ind, void *v)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(v != NULL);
	assert(ind >= 0);

	assert(d->use <= d->cap);
	assert(ind <= d->use);
	assert(d->lsize >= d->cap);

	const size_t rind = ind * sizeof(uint32_t);
	const unsigned char *rdata = d->data + HEADER_LENGTH;
#if NOSERIAL
	memcpy(v, &rdata[rind], sizeof(uint32_t));
#else
	*((uint32_t *)v) =
		(((uint32_t)rdata[rind] << 24) | ((uint32_t)rdata[rind + 1] << 16) |
		 ((uint32_t)rdata[rind + 2] << 8) | ((uint32_t)rdata[rind + 3] << 0));
#endif
	return;
}

static enum DARRAY_ERROR
darray_uint64_push(struct darray *d, const void *v)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(v != NULL);

	assert(d->use <= d->cap);
	assert(d->lsize >= d->cap);

	enum DARRAY_ERROR rc;
	if ((rc = darray_ensure_size(d))) {
		goto fail_darray_ensure_size;
	}
	assert(d->use < d->cap);

	const size_t rind = d->use++ * sizeof(uint64_t);
	assert(rind >= d->use - 1);
	unsigned char *rdata = d->data + HEADER_LENGTH;

#if NOSERIAL
	memcpy(&rdata[rind], v, sizeof(uint64_t));
#else
	rdata[rind] = (*((const uint64_t *) v) >> 56);
	rdata[rind + 1] = (*((const uint64_t *) v) >> 48);
	rdata[rind + 2] = (*((const uint64_t *) v) >> 40);
	rdata[rind + 3] = (*((const uint64_t *) v) >> 32);
	rdata[rind + 4] = (*((const uint64_t *) v) >> 24);
	rdata[rind + 5] = (*((const uint64_t *) v) >> 16);
	rdata[rind + 6] = (*((const uint64_t *) v) >> 8);
	rdata[rind + 7] = (*((const uint64_t *) v) >> 0);
#endif
	return SUCCESS;

fail_darray_ensure_size:
	assert(rc != SUCCESS);
	return rc;
}

static void
darray_uint64_get(const struct darray *d, const size_t ind, void *v)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(v != NULL);
	assert(ind >= 0);

	assert(d->use <= d->cap);
	assert(ind <= d->use);
	assert(d->lsize >= d->cap);

	const size_t rind = ind * sizeof(uint64_t);
	const unsigned char *rdata = d->data + HEADER_LENGTH;
#if NOSERIAL
	memcpy(v, &rdata[rind], sizeof(uint64_t));
#else
	*((uint64_t *)v) =
		(((uint64_t)rdata[rind] << 56) | ((uint64_t)rdata[rind + 1] << 48) |
		((uint64_t)rdata[rind + 2] << 40) | ((uint64_t)rdata[rind + 3] << 32) |
		((uint64_t)rdata[rind + 4] << 24) | ((uint64_t)rdata[rind + 5] << 16) |
		((uint64_t)rdata[rind + 6] << 8) | ((uint64_t)rdata[rind + 7] << 0));
#endif
	return;
}

static enum DARRAY_ERROR
darray_bset_push(struct darray *d, const void *v)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(v != NULL);

	assert(d->use <= d->cap);

	enum DARRAY_ERROR rc;
	if ((rc = darray_ensure_size(d))) {
		goto fail_darray_ensure_size;
	}
	assert(d->use < d->cap);

	unsigned char *rdata = d->data + HEADER_LENGTH;
	const size_t rind = d->use / (sizeof(unsigned int));
	const size_t roff = d->use++ % (sizeof(unsigned int));

	if ((*(const unsigned int *)v)) {
		rdata[rind] |= (1 << roff);
	} else {
		rdata[rind] &= ~(1 << roff);
	}

	return SUCCESS;

fail_darray_ensure_size:
	assert(rc != SUCCESS);
	return rc;
}

static void darray_bset_get(const struct darray *d, const size_t ind, void *v)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(v != NULL);
	assert(ind >= 0);

	assert(d->use <= d->cap);
	assert(ind <= d->use);

	const size_t rind = ind / (sizeof(unsigned int));
	const size_t roff = ind % (sizeof(unsigned int));
	const unsigned char *rdata = d->data + HEADER_LENGTH;

	*((unsigned int *) v) = rdata[rind] & (1 << roff);
	return;
}

#include <stdio.h>
static void darray_uint_print_all(struct darray *d)
{
	assert(d->path != NULL);
	assert(d->data != NULL);
	assert(d->use <= d->cap);

	printf("Darray %s:\n", d->path);
	for (size_t i = 0; i < d->use; ++i) {
		uint32_t val;
		d->get(d, i, &val);
		printf("%4u ", val);
		if ((i - 1) % 100 == 0) {
			printf("\n");
		}
	}
	printf("\n");
	return;
}

static void darray_bset_print_all(struct darray *d)
{
	assert(d->path != NULL);
	assert(d->data != NULL);
	assert(d->use <= d->cap);

	unsigned int val = 0;
	printf("Darray %s:\n", d->path);
	for (size_t i = 0; i < d->use; ++i) {
		d->get(d, i, &val);
		if (val) {
			printf("%4zu ", i);
		}
		if ((i - 1) % 100 == 0) {
			printf("\n");
		}
	}
	printf("\n");
	return;
}

#if TEST
int main(void)
{
	int rc = 0;
	struct darray d;

	//enum VALUE_TYPE t = UNSIGNED_INT;
	enum VALUE_TYPE t = BITSET;
	size_t vs = sizeof(uint8_t);

	if ((rc = darray_init(&d, 0, &t, &vs,
		"/Users/nick/scratch/mmap_dynamic_array", "test", "eves")) != SUCCESS) {
		printf("Error: %s\n", darray_strerror(rc));
		goto fail_darray_init;
	}

	for (uint64_t i = 0; i < 10000; ++i) {
		if ((rc = d.push(&d, &i)) != SUCCESS) {
			printf("Error: %s\n", darray_strerror(rc));
			goto fail_darray_append;
		}
	}

	switch (t) {
	case UNSIGNED_INT:
		darray_uint_print_all(&d);
		break;
	case BITSET:
		darray_bset_print_all(&d);
		break;
	}

fail_darray_append:
	darray_free(&d);
fail_darray_init:
	return rc == SUCCESS ? 0 : rc;
}
#endif
