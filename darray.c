#include "darray.h"

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
 * 	Specifically in darray_*_push(), darray_*_get(), as well as the switch() in
 * 	darray_init().
 * 	Also find a way to pretty-up the SERIAL vs NOSERIAL code. #define is ugly.
 *
 * TODO: Finalize error handling.
 *
 * TODO: Double check with someone else that the bitarray is being used properly
 *
 * TODO: Seriously, the HEADER_LENGTH math is disgustingly ugly. Fix it up.
*/

#define HEADER_IDENTIFIER 0xDEADBEEFCAFED00D
#define HEADER_VERSION 0
#define HEADER_LENGTH 6*sizeof(uint64_t)

struct darray {
	uint64_t use;
	uint64_t cap;
	/* items below this point are not saved persistently, they're recreated
	 * by init().
	*/
	size_t lsize; /* Literal size of the backend. */
	char *path;
	unsigned char *data;
	int (*push)(struct darray *, const void *);
	void (*get)(const struct darray *, const size_t, void *);
};

static int darray_uint8_push(struct darray *d, const void *v);
static void darray_uint8_get(const struct darray *d, const size_t ind, void *v);
static int darray_uint16_push(struct darray *d, const void *v);
static void darray_uint16_get(const struct darray *d,const size_t ind, void *v);
static int darray_uint32_push(struct darray *d, const void *v);
static void darray_uint32_get(const struct darray *d,const size_t ind, void *v);
static int darray_uint64_push(struct darray *d, const void *v);
static void darray_uint64_get(const struct darray *d,const size_t ind, void *v);
static int darray_bset_push(struct darray *d, const void *v);
static void darray_bset_get(const struct darray *d, const size_t ind, void *v);

#ifndef MALLOC
/* TODO: Change semantics to take in a fd and return an error code? */
/*
 * Stretches the file backend of the given darray to size new_size, so that
 * it can be mmap()'d to the new size.
 *
 * Assumes that the first argument points to a darray with a d->path pointing to
 * a valid location in the filesystem.
 *
 * Returns a file descriptor to the path on success, a negative error code
 * otherwise.
*/
static int darray_stretch_size(struct darray *d, const size_t new_size)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->path != NULL);
	assert(new_size > 0);

	int rc = 0;
	const int fd = open(d->path, O_RDWR|O_CREAT|O_NOFOLLOW);
	if (fd < 0) {
		rc = -1;
		goto fail_open;
	}

	if (lseek(fd, new_size, SEEK_SET) == -1) {
		rc = -2;
		goto fail_lseek;
	}

	if (write(fd, "", 1) == -1) {
		rc = -3;
		goto fail_write;
	}

	assert(fd > 0);
	return fd;

fail_write:
fail_lseek:
	close(fd);
fail_open:
	assert(rc <= 0);
	return rc;
}
#endif

#ifndef MALLOC
static int darray_alloc_mmap(struct darray *d, size_t desired_size)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->path != NULL);

	int rc = 0; 

	struct stat statb;
	/* TODO: Change the below code to continue on if the stat() error is that
	 * the file isn't found so that it can be created instead. Basically all
	 * that needs to happen is statb.st_size needs to be set to zero.
	*/
	if ((rc = stat(d->path, &statb))) {
		rc = -1;
		goto fail_stat;
	}

	int fd = -1;
	if ((desired_size == 0) && (statb.st_size == 0)) {
		/* Attempt to map the file as-is. */
		return 1; /* Not an error condition, so we don't jump to fail_* */
	}

	if (desired_size <= (size_t)statb.st_size) {
		if ((fd = open(d->path, O_RDWR|O_NOFOLLOW)) < 0) {
			rc = -3;
			goto fail_open;
		}
		/* WARNING: for optimal (and, as the back-end grows larger,  reasonable,
		 * file size usage, this line assumes that this program (or some
		 * version thereof) is the only thing which can extend the back-end's
		 * file size.
		 *
		 * This is due to the below line, which otherwise would have to be
		 * made a special case for desired_size == 0 and creates ugly code.
		*/
		desired_size = statb.st_size;
	} else {
		/* Extend the file as needed */
		if ((fd = darray_stretch_size(d, desired_size)) < 0) {
			rc = -4;
			goto fail_extend_file;
		}
	} 

	assert(fd > 0);

	void *new_data
		= mmap(0, desired_size, PROT_READ|PROT_WRITE, MAP_FILE|MAP_SHARED, fd, 0);
	if (!new_data) {
		rc = -5;
		goto fail_mmap;
	}

	if (close(fd) == -1) {
		rc = -6;
		goto fail_close;
	}

	assert(new_data != NULL);
	d->data = new_data;
	d->lsize = desired_size;

	/* Post conditions */
	assert(d->data != NULL);
	return 0;

fail_close:
	munmap(new_data, desired_size);
fail_mmap:
	close(fd);
fail_open:
fail_extend_file:
fail_stat:
	assert(rc < 0);
	return rc;
}
#else
static int darray_alloc_malloc(struct darray *d, size_t desired_size)
{
	/* Preconditions */
	assert(d != NULL);
	assert(desired_size > 0);

	int rc = 0;
	void *new_data = realloc(d->data, desired_size);
	if (!new_data) {
		rc = -1;
		goto fail_realloc;
	}
	assert(new_data != NULL);

	d->data = new_data;
	d->lsize = desired_size;

	/* Postconditions */
	assert(d->data != NULL);
	return 0;

	free(new_data);
fail_realloc:
	assert(rc < 0);
	return rc;
}
#endif

/*
 * Attempts to change the backend of the given darray (malloc() or mmap()) to
 * the desired_size. If desired_size is set to zero, an attempt will be made
 * to map the file as-is, which will fail in the usual cases or if the file
 * is zero size (has not been created).
*/
static int darray_alloc(struct darray *d, size_t desired_size)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->path != NULL);

	int rc = -1;
#ifndef MALLOC
	rc = darray_alloc_mmap(d, desired_size);
#else
	rc = darray_alloc_malloc(d, desired_size);
#endif

	/* Postconditions */
	if (rc == 0) {
		assert(d->data != NULL);
	} else {
		assert(d->data == NULL);
	}
	return rc;
}

/*
 * Ensures that there is room for another element in the darray's backend, and
 * atttemps to expand it otherwise.
*/
static int darray_ensure_size(struct darray *d)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->use <= d->cap);
	assert(d->data != NULL);

	int rc = 0;
	if (d->use < d->cap) { /* Early exit, since we have no work to do. */
		/* Post conditions */
		assert(d->data != NULL);
		return 0;
	}

	/* Otherwise extend the size of the array to make room for the insert. */
	const int expn_factor = 2; /* Replace as needed. */
	const size_t new_size = d->lsize * expn_factor;
	const size_t new_cap = d->cap * expn_factor;
	if ((new_size < d->lsize) || (new_cap < d->cap)) {
		rc = 1;
		goto fail_int_wrap;
	}
	assert(new_size > d->lsize);
	assert(new_cap > d->cap);

	if ((rc = darray_alloc(d, new_size))) {
		goto fail_darray_alloc;
	}

	assert(d->data != NULL);
	d->cap = new_cap;

	/* Post_conditions. */
	assert(d->data != NULL);
	assert(d->lsize > 0);
	assert(d->use < d->cap);
	return 0;

fail_darray_alloc:
fail_int_wrap:
	assert(rc != 0);
	return rc;
}

#ifndef MALLOC
static size_t
uint64_serialize(const uint64_t val, unsigned char *str)
{
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

static uint64_t
uint64_deserialize(const unsigned char *str)
{
    return ((uint64_t)str[0] << 56) | ((uint64_t)str[1] << 48) |
        ((uint64_t)str[2] << 40) | ((uint64_t)str[3] << 32) |
        ((uint64_t)str[4] << 24) | ((uint64_t)str[5] << 16) |
        ((uint64_t)str[6] << 8) | ((uint64_t)str[7] << 0);
}
#endif

/* Allocates memory for the path 'dir/name.ext' */
static char *
create_path(const char *dir, const char *name, const char *ext)
{
	assert(dir != NULL);
	assert(name != NULL);
	assert(ext != NULL);

	size_t dir_len = strlen(dir);
	size_t name_len = strlen(name);
	size_t ext_len = strlen(ext);

	/* Additional space for a slash, a period, and a null terminator. */
	char *path = malloc(dir_len + name_len + ext_len + 3);
	if (!path) {
		return NULL;
	}

	assert(path != NULL);

	/* Copy over appropriate fields, with unix path conventions. */
	memcpy(path, dir, dir_len);
	path[dir_len] = '/';
	memcpy(path + dir_len + 1, name, name_len);
	path[dir_len + name_len + 1] = '.';
	memcpy(path + dir_len + name_len + 2, ext, ext_len + 1); /* null too */

	/* Postconditions. */
	assert(path[dir_len + name_len + ext_len + 2] == '\0');

	return path;
}

#ifndef MALLOC
static int
darray_attempt_restore(struct darray *d,
		enum VALUE_TYPE *val_type, size_t *val_size)
{
	/* Preconditions */
	assert(d != NULL);
	assert(val_type != NULL);
	assert(val_size != NULL);

	int rc = 0;

	rc = darray_alloc(d, 0); /* Signal darray_alloc() to map the whole file. */

	switch(rc) {
	default: /* Error in darray_alloc */
		goto fail_darray_alloc;
	case 1: /* The file is empty. */
		assert(d->data == NULL);
		return 1; /* Not a failure case! */
	
	case 0:  /* The file has stuff. Check it out. */
		break;
	}

	assert(d->data != NULL);

	/* Attempt to deserialize the struct from the file. */
	if (uint64_deserialize(d->data) != 0xDEADBEEFCAFED00D) {
		/* Bad file identifier. */
		rc = 2;
		goto fail_file;
	}	
	
	if (uint64_deserialize(d->data + sizeof(uint64_t)) > 0) {
		/* We can't read files of this version. */
		rc = 3;
		goto fail_version;
	}

	/* Ensure that the type is as we expect. */
	const uint64_t decoded_value_type =
		uint64_deserialize(d->data + 2 * sizeof(uint64_t));
	enum VALUE_TYPE persisted_vtype;
	switch(decoded_value_type) {
	case 0:
		persisted_vtype = UNSIGNED_INT;
		break;
	case 1:
		persisted_vtype = BITSET;
		break;
	default:
		rc = 4;
		goto fail_value_type;
		break;
	}

	if (persisted_vtype != *val_type) {
		*val_type = persisted_vtype;
		rc = 5;
		goto fail_value_type;
	}

	const uint64_t persisted_vsize =
		uint64_deserialize(d->data + 3 * sizeof(uint64_t));

	/* Value_size is arbitrary for bitsets. */
	if ((persisted_vtype != BITSET) && (persisted_vsize != *val_size)){
		*val_size = persisted_vsize;
		rc = 6;
		goto fail_value_size;
	}

	d->use = uint64_deserialize(d->data + 4 * sizeof(uint64_t));
	d->cap = uint64_deserialize(d->data + 5 * sizeof(uint64_t));
	if (d->cap < d->use) {
		rc = 7;
		goto fail_usecap;
	}

	/* Postconditions */
	assert(d != NULL);
	assert(d->cap >= d->use);
	assert(d->data != NULL);
	assert(d->path != NULL);
	assert(d->lsize > 0);
	if (persisted_vtype != BITSET) {
		assert(d->lsize > d->cap);
	}
	return 0;

fail_usecap:
fail_value_type:
fail_value_size:
fail_file:
fail_version:
	munmap(d->data, d->lsize);
	d->data = NULL;
fail_darray_alloc:
	/* Post conditions */
	assert(d->data == NULL);
	assert(d->path == NULL);
	assert(rc != 0);
	return rc;
}
#endif

int darray_init(struct darray *d, const size_t val_cnt,
        enum VALUE_TYPE *val_type, size_t *val_size,
        const char *dir, const char *name, const char *ext)
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

	int rc = 0;

	d->data = NULL;
	d->path = create_path(dir, name, ext);
	if (!d->path) {
		rc = 1;
		goto fail_path_malloc;
	}

	assert(d->path != NULL);

#ifndef MALLOC
	/* Initialize the rest of the darray struct, using the persistent version
	 * stored on the file if needed.
	*/
	rc = darray_attempt_restore(d, val_type, val_size);
#else 
	/* Hacky abuse of the above function's return codes to merge code paths. */
	rc = 1; 
#endif 

	switch(rc) {
	case 0:
		break;
	default:
		goto fail_darray_attempt_restore;
	case 1:
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
		if (alloc_size <= d->cap) {
			rc = 7;
			goto fail_lsize_wrap;
		}
		assert(alloc_size > d->cap);
		break;
	}
	case BITSET: {
		d->push = darray_bset_push;
		d->get = darray_bset_get;
		/* Note, we reserve space for the largest possible integer (uint64_t) so
	 	* that no matter what architecture we're working on, it will be able to
	 	* operate at its native word size for maximum efficiency. (Bitsets are
	 	* endian independent, so the only portability issue is word size).
		* (Otherwise, we might run into issues with an array allocated on an
		* arch with a small worlsize (e.g. 16 bits) on an arch with a bigger
		* word size (e.g. 32 or 64 bit).
		*
		* This function below gives us the rounded up count of uint64's needed
		* given our val_cnt.
		*/
		alloc_size = (sizeof(uint64_t)-1 + d->cap / sizeof(uint64_t));
		break;
	}
	}

	assert(d->push != NULL);
	assert(d->get != NULL);
	assert(alloc_size > 0);

	if (alloc_size + HEADER_LENGTH < alloc_size) {
		rc = 8;
		goto fail_alloc_size_wrap;
	}
	alloc_size += HEADER_LENGTH;

	if ((!d->data) && (rc = darray_alloc(d, alloc_size))) {
		/* Initialization failed. Short circuiting ensures no double-alloc. */
		goto fail_darray_alloc;
	}
	assert(d->data != NULL);
	d->lsize = alloc_size;

	/* Post-conditions */
	assert(d->cap != 0);
	assert(d->use <= d->cap);
	assert(rc == 0);
	assert(d->data != NULL);
	assert(d->path != NULL);
	assert(d->push != NULL);
	assert(d->get != NULL);
	return 0;

fail_alloc_size_wrap:
#ifndef MALLOC
	munmap(d->data, d->lsize);
#else
	free(d->data);
#endif
	d->data = NULL;
fail_darray_alloc:
fail_darray_attempt_restore:
fail_lsize_wrap:
	free(d->path);
	d->path = NULL;
fail_path_malloc:

	/* Post conditions */
	assert(d->data == NULL);
	assert(d->path == NULL);
	assert(rc != 0);
	return rc;
}

/* TODO: CLEAN UP THIS CODE! */
void darray_free(struct darray *d)
{
	/* Preconditions */
	assert(d->use <= d->cap);
	assert(d->lsize >= d->cap);

	free(d->path);
#ifndef MALLOC
	uint64_t temp = HEADER_IDENTIFIER;
	uint64_serialize(temp, d->data + 0 * sizeof(uint64_t));
	temp = HEADER_VERSION;
	uint64_serialize(temp, d->data + 1 * sizeof(uint64_t));
	temp = 0; // UNSIGNED_INTEGER
	uint64_serialize(temp, d->data + 2 * sizeof(uint64_t));
	temp = sizeof(uint64_t); // uint32_t
	uint64_serialize(temp, d->data + 3 * sizeof(uint64_t));
	temp = d->use;
	uint64_serialize(temp, d->data + 4 * sizeof(uint64_t));
	temp = d->cap;
	uint64_serialize(temp, d->data + 5 * sizeof(uint64_t));

	msync(d->data, d->lsize, MS_SYNC);
	munmap(d->data, d->lsize);
#else
	free(d->data);
#endif
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
}

static int darray_uint8_push(struct darray *d, const void *v)
{
	/* Preconditions */
	assert(d->use <= d->cap);
	assert(d->lsize >= d->cap);

	int rc = 0;
	if ((rc = darray_ensure_size(d))) {
		goto fail_darray_ensure_size;
	}
	assert(d->use < d->cap);

	const size_t rind = d->use++ * sizeof(uint8_t);
	assert(rind >= d->use - 1);
#if NOSERIAL
	memcpy(&d->data[rind] + HEADER_LENGTH, v, sizeof(uint8_t));
#else
	*(HEADER_LENGTH + &d->data[rind + 0]) = (*((const uint8_t *) v) >> 0);
#endif
	return 0;

fail_darray_ensure_size:
	assert(rc != 0);
	return rc;
}

static void darray_uint8_get(const struct darray *d, const size_t ind, void *v)
{
	/* Preconditions */
	assert(d->use <= d->cap);
	assert(ind <= d->use);
	assert(d->lsize >= d->cap);

	const size_t rind = ind * sizeof(uint8_t);
	assert(rind >= ind - 1);
#if NOSERIAL
	memcpy(v, &d->data[rind] + HEADER_LENGTH, sizeof(uint8_t));
#else
	*((uint8_t *)v) = ((uint8_t)*(HEADER_LENGTH + &d->data[rind]) << 0);
#endif
	return;
}

static int darray_uint16_push(struct darray *d, const void *v)
{
	/* Preconditions */
	assert(d->use <= d->cap);
	assert(d->lsize >= d->cap);

	int rc = 0;
	if ((rc = darray_ensure_size(d))) {
		goto fail_darray_ensure_size;
	}
	assert(d->use < d->cap);

	const size_t rind = d->use++ * sizeof(uint16_t);
	assert(rind >= d->use - 1);
#if NOSERIAL
	memcpy(&d->data[rind] + HEADER_LENGTH, v, sizeof(uint16_t));
#else
	*(HEADER_LENGTH + &d->data[rind + 0]) = (*((const uint16_t *) v) >> 8);
	*(HEADER_LENGTH + &d->data[rind + 1]) = (*((const uint16_t *) v) >> 0);
#endif
	return 0;

fail_darray_ensure_size:
	assert(rc != 0);
	return rc;
}

static void darray_uint16_get(const struct darray *d, const size_t ind, void *v)
{
	/* Preconditions */
	assert(d->use <= d->cap);
	assert(ind <= d->use);
	assert(d->lsize >= d->cap);

	const size_t rind = ind * sizeof(uint16_t);
#if NOSERIAL
	memcpy(v, &d->data[rind] + HEADER_LENGTH, sizeof(uint16_t));
#else
	*((uint16_t *)v) =
		(((uint16_t)*(HEADER_LENGTH + &d->data[rind]) << 8) |
		 ((uint16_t)*(HEADER_LENGTH + &d->data[rind+1]) << 0));
#endif
	return;
}

static int darray_uint32_push(struct darray *d, const void *v)
{
	/* Preconditions */
	assert(d->use <= d->cap);
	assert(d->lsize >= d->cap);

	int rc = 0;
	if ((rc = darray_ensure_size(d))) {
		goto fail_darray_ensure_size;
	}
	assert(d->use < d->cap);

	const size_t rind = d->use++ * sizeof(uint32_t);
	assert(rind >= d->use - 1);
#if NOSERIAL
	memcpy(&d->data[rind] + HEADER_LENGTH, v, sizeof(uint32_t));
#else
	*(HEADER_LENGTH + &d->data[rind + 0]) = (*((const uint32_t *) v) >> 24);
	*(HEADER_LENGTH + &d->data[rind + 1]) = (*((const uint32_t *) v) >> 16);
	*(HEADER_LENGTH + &d->data[rind + 2]) = (*((const uint32_t *) v) >> 8);
	*(HEADER_LENGTH + &d->data[rind + 3]) = (*((const uint32_t *) v) >> 0);
#endif
	return 0;

fail_darray_ensure_size:
	assert(rc != 0);
	return rc;
}

static void darray_uint32_get(const struct darray *d, const size_t ind, void *v)
{
	/* Preconditions */
	assert(d->use <= d->cap);
	assert(ind <= d->use);
	assert(d->lsize >= d->cap);

	const size_t rind = ind * sizeof(uint32_t);
#if NOSERIAL
	memcpy(v, &d->data[rind] + HEADER_LENGTH, sizeof(uint32_t));
#else
	*((uint32_t *)v) =
		(((uint32_t)*(HEADER_LENGTH + &d->data[rind]) << 24) |
		 ((uint32_t)*(HEADER_LENGTH + &d->data[rind+1]) << 16) |
		((uint32_t)*(HEADER_LENGTH + &d->data[rind+2]) << 8) |
		((uint32_t)*(HEADER_LENGTH + &d->data[rind+3]) << 0));
#endif
	return;
}

static int darray_uint64_push(struct darray *d, const void *v)
{
	/* Preconditions */
	assert(d->use <= d->cap);
	assert(d->lsize >= d->cap);

	int rc = 0;
	if ((rc = darray_ensure_size(d))) {
		goto fail_darray_ensure_size;
	}
	assert(d->use < d->cap);

	const size_t rind = d->use++ * sizeof(uint64_t);
	assert(rind >= d->use - 1);
#if NOSERIAL
	memcpy(&d->data[rind] + HEADER_LENGTH, v, sizeof(uint64_t));
#else
	*(HEADER_LENGTH + &d->data[rind + 0]) = (*((const uint64_t *) v) >> 56);
	*(HEADER_LENGTH + &d->data[rind + 1]) = (*((const uint64_t *) v) >> 48);
	*(HEADER_LENGTH + &d->data[rind + 2]) = (*((const uint64_t *) v) >> 40);
	*(HEADER_LENGTH + &d->data[rind + 3]) = (*((const uint64_t *) v) >> 32);
	*(HEADER_LENGTH + &d->data[rind + 4]) = (*((const uint64_t *) v) >> 24);
	*(HEADER_LENGTH + &d->data[rind + 5]) = (*((const uint64_t *) v) >> 16);
	*(HEADER_LENGTH + &d->data[rind + 6]) = (*((const uint64_t *) v) >> 8);
	*(HEADER_LENGTH + &d->data[rind + 7]) = (*((const uint64_t *) v) >> 0);
#endif
	return 0;

fail_darray_ensure_size:
	assert(rc != 0);
	return rc;
}

static void darray_uint64_get(const struct darray *d, const size_t ind, void *v)
{
	/* Preconditions */
	assert(d->use <= d->cap);
	assert(ind <= d->use);
	assert(d->lsize >= d->cap);

	const size_t rind = ind * sizeof(uint64_t);
#if NOSERIAL
	memcpy(v, &d->data[rind] + HEADER_LENGTH, sizeof(uint64_t));
#else
	*((uint64_t *)v) =
		(((uint64_t)*(HEADER_LENGTH + &d->data[rind]) << 56) |
		 ((uint64_t)*(HEADER_LENGTH + &d->data[rind+1]) << 48) |
		((uint64_t)*(HEADER_LENGTH + &d->data[rind+2]) << 40) |
		((uint64_t)*(HEADER_LENGTH + &d->data[rind+3]) << 32) |
		((uint64_t)*(HEADER_LENGTH + &d->data[rind+4]) << 24) |
		((uint64_t)*(HEADER_LENGTH + &d->data[rind+5]) << 16) |
		((uint64_t)*(HEADER_LENGTH + &d->data[rind+6]) << 8) |
		((uint64_t)*(HEADER_LENGTH + &d->data[rind+7]) << 0));
#endif
	return;
}

static int darray_bset_push(struct darray *d, const void *v)
{
	/* Preconditions */
	assert(d->use <= d->cap);

	int rc = 0;
	if ((rc = darray_ensure_size(d))) {
		goto fail_darray_ensure_size;
	}
	assert(d->use < d->cap);

	const size_t rind = d->use / (sizeof(unsigned int));
	const size_t roff = d->use++ % (sizeof(unsigned int));

	/* TODO: Fix this math. */
	if ((*(const unsigned int *)v)) {
		*(&d->data[rind] + HEADER_LENGTH) |= (1 << roff);
	} else {
		*(&d->data[rind] + HEADER_LENGTH) &= ~(1 << roff);
	}

	return 0;

fail_darray_ensure_size:
	assert(rc != 0);
	return rc;
}

static void darray_bset_get(const struct darray *d, const size_t ind, void *v)
{
	/* Preconditions */
	assert(d->use <= d->cap);
	assert(ind <= d->use);

	const size_t rind = ind / (sizeof(unsigned int));
	const size_t roff = ind % (sizeof(unsigned int));

	*((unsigned int *) v) = *(&d->data[rind] + HEADER_LENGTH) & (1 << roff);
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
	for (size_t i = 0; i < 10000000; ++i) {
	//for (size_t i = 0; i < d->use; ++i) { TEST
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

	enum VALUE_TYPE t = UNSIGNED_INT;
	//enum VALUE_TYPE t = BITSET;
	size_t vs = sizeof(uint64_t);

	if ((rc = darray_init(&d, 0, &t, &vs,
			"/Users/nick/scratch/mmap_dynamic_array", "test", "eves"))) {
		printf("Error. %d\n", rc);
		goto fail_darray_init;
	}

	for (uint64_t i = 0; i < 10000000; ++i) {
		if ((rc = d.push(&d, &i))) {
			printf("Error, malloc.\n");
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
	return rc;
}
#endif
