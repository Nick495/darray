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
 * TODO: Double check with someone else that the bitarray is being used properly
 *
 * TODO: Finalize error handling.
 * TODO: Go back over the error-codepaths for functions. I think a few of them
 * are wrong.
*/

#define HEADER_IDENTIFIER 0xDEADBEEFCAFED00D
#define HEADER_VERSION 0
#define HEADER_LENGTH 6*sizeof(uint64_t)

/* Only for function prototypes and structs so they'll fit in 80-columns. */
typedef enum DARRAY_ERROR de;

struct darray {
	uint64_t use;
	uint64_t cap;
	/* items below this point are not saved persistently, they're recreated
	 * by init().
	*/
	size_t lsize; /* Literal size of the backend. */
	char *path;
	unsigned char *data;
	de (*push)(struct darray *, const void *);
	void (*get)(const struct darray *, const size_t, void *);
};

static de darray_uint8_push(struct darray *d, const void *v);
static void darray_uint8_get(const struct darray *d, const size_t ind, void *v);
static de darray_uint16_push(struct darray *d, const void *v);
static void darray_uint16_get(const struct darray *d,const size_t ind, void *v);
static de darray_uint32_push(struct darray *d, const void *v);
static void darray_uint32_get(const struct darray *d,const size_t ind, void *v);
static de darray_uint64_push(struct darray *d, const void *v);
static void darray_uint64_get(const struct darray *d,const size_t ind, void *v);
static de darray_bset_push(struct darray *d, const void *v);
static void darray_bset_get(const struct darray *d, const size_t ind, void *v);

#ifndef MALLOC
static enum DARRAY_ERROR
darray_stretch_size(struct darray *d, const size_t new_size, int *fd)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->path != NULL);
	assert(fd != NULL);
	assert(new_size > 0);

	enum DARRAY_ERROR rc;
	*fd = open(d->path, O_RDWR|O_CREAT|O_NOFOLLOW);
	if (*fd < 0) {
		rc = D_OPEN;
		goto fail_open;
	}

	if (lseek(*fd, new_size, SEEK_SET) == -1) {
		rc = D_LSEEK;
		goto fail_lseek;
	}

	if (write(*fd, "", 1) == -1) {
		rc = D_WRITE;
		goto fail_write;
	}

	/* Postconditions */
	assert(d != NULL);
	assert(d->path != NULL);
	assert(fd != NULL);
	assert(*fd > 0);
	return SUCCESS;

fail_write:
fail_lseek:
	close(*fd);
fail_open:
	assert(rc != SUCCESS);
	return rc;
}

static enum DARRAY_ERROR
darray_alloc_mmap(struct darray *d, size_t desired_size)
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
	if ((desired_size == 0) && (statb.st_size == 0)) {
		/* Postconditions */
		assert(d != NULL);
		assert(d-> path != NULL);
		/* Not an error condition, so we don't jump to fail_* */
		return EMPTY_FILE;
	}

	if (desired_size <= (size_t)statb.st_size) {
		if ((fd = open(d->path, O_RDWR|O_NOFOLLOW)) < 0) {
			rc = D_OPEN;
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
		if ((rc = darray_stretch_size(d, desired_size, &fd)) != SUCCESS) {
			goto fail_extend_file;
		}
	} 

	assert(fd > 0);

	void *new_data
		= mmap(0, desired_size, PROT_READ|PROT_WRITE, MAP_FILE|MAP_SHARED, fd, 0);
	if (!new_data) {
		rc = D_MMAP;
		goto fail_mmap;
	}

	if (close(fd) == -1) {
		rc = D_CLOSE;
		goto fail_close;
	}

	assert(new_data != NULL);
	d->data = new_data;
	d->lsize = desired_size;

	/* Post conditions */
	assert(d != NULL);
	assert(d->path != NULL);
	assert(d->data != NULL);
	assert(d->lsize >= desired_size);
	return SUCCESS;

fail_close:
	munmap(new_data, desired_size);
fail_mmap:
	close(fd);
fail_open:
fail_extend_file:
fail_stat:
	assert(rc != SUCCESS && rc != EMPTY_FILE);
	return rc;
}

#else

static enum DARRAY_ERROR
darray_alloc_malloc(struct darray *d, size_t desired_size)
{
	/* Preconditions */
	assert(d != NULL);
	assert(desired_size > 0);

	enum DARRAY_ERROR rc;
	void *new_data = realloc(d->data, desired_size);
	if (!new_data) {
		rc = D_MALLOC;
		goto fail_realloc;
	}
	assert(new_data != NULL);

	d->data = new_data;
	d->lsize = desired_size;

	/* Postconditions */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(d->lsize >= desired_size);
	return 0;

	free(new_data);
fail_realloc:
	assert(rc != SUCCESS && rc != EMPTY_FILE);
	return rc;
}

#endif

/*
 * Attempts to change the backend of the given darray (malloc() or mmap()) to
 * the desired_size. If desired_size is set to zero, an attempt will be made
 * to map the file as-is, which will fail in the usual cases or if the file
 * is zero size (has not been created).
*/
static enum DARRAY_ERROR
darray_alloc(struct darray *d, size_t desired_size)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->path != NULL);

	enum DARRAY_ERROR rc;
#ifndef MALLOC
	rc = darray_alloc_mmap(d, desired_size);
#else
	rc = darray_alloc_malloc(d, desired_size);
#endif

	/* Postconditions */
	if (rc == SUCCESS) {
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
static enum DARRAY_ERROR
darray_ensure_size(struct darray *d)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->use <= d->cap);
	assert(d->data != NULL);

	enum DARRAY_ERROR rc;
	if (d->use < d->cap) { /* Early exit, since we have no work to do. */
		/* Post conditions */
		assert(d != NULL);
		assert(d->use <= d->cap);
		assert(d->data != NULL);
		return SUCCESS;
	}

	/* Otherwise extend the size of the array to make room for the insert. */
	const int expn_factor = 2; /* Replace as needed. */
	const size_t new_size = d->lsize * expn_factor;
	const size_t new_cap = d->cap * expn_factor;
	if ((new_size < d->lsize) || (new_cap < d->cap)) {
		rc = D_WRAP;
		goto fail_uint_wrap;
	}
	assert(new_size > d->lsize);
	assert(new_cap > d->cap);

	if ((rc = darray_alloc(d, new_size))) {
		goto fail_darray_alloc;
	}

	assert(d->data != NULL);
	d->cap = new_cap;

	/* Post_conditions. */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(d->lsize > 0);
	assert(d->use <= d->cap);
	return 0;

fail_darray_alloc:
fail_uint_wrap:
	assert(rc != SUCCESS);
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

static size_t
value_type_serialize(const enum VALUE_TYPE vt, unsigned char *str)
{
	switch(vt) {
	case UNSIGNED_INT:
		return uint64_serialize(0, str);
		break;
	case BITSET:
		return uint64_serialize(1, str);
		break;
	}
}

static enum DARRAY_ERROR
value_type_deserialize(const unsigned char *str, enum VALUE_TYPE *v)
{
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
	uint64_t temp = HEADER_IDENTIFIER;
	size_t offset = 0;
	offset += uint64_serialize(temp, d->data + offset * sizeof(uint64_t));
	temp = HEADER_VERSION;
	offset += uint64_serialize(temp, d->data + offset * sizeof(uint64_t));
	temp = 0; 
	offset += value_type_serialize(valtyp, d->data + offset * sizeof(uint64_t));
	temp = value_size; 
	offset += uint64_serialize(temp, d->data + offset * sizeof(uint64_t));
	temp = d->use;
	offset += uint64_serialize(temp, d->data + offset * sizeof(uint64_t));
	temp = d->cap;
	offset += uint64_serialize(temp, d->data + offset * sizeof(uint64_t));

	return;
}

static enum DARRAY_ERROR
darray_header_deserialize(struct darray *d, enum VALUE_TYPE *val_type,
		size_t *val_size)
{
	/* Preconditions. */
	assert(d != NULL);
	assert(d->data != NULL);
	assert(val_type != NULL);
	assert(val_size != NULL);

	enum DARRAY_ERROR rc = SUCCESS;

	/* Attempt to deserialize the struct from the file. */
	if (uint64_deserialize(d->data) != (uint64_t)HEADER_IDENTIFIER) {
		/* Bad file identifier. */
		rc = D_BAD_IDENTIFIER;
		goto fail_file;
	}	
	
	if (uint64_deserialize(d->data + sizeof(uint64_t)) > HEADER_VERSION) {
		/* We can't read files of this version. */
		rc = D_BAD_VERSION;
		goto fail_version;
	}

	/* Ensure that the type is as we expect. */
	if ((rc = value_type_deserialize(d->data + 2 * sizeof(uint64_t), val_type))
			!= SUCCESS) {
		goto fail_value_type_deserialize;
	}


	const uint64_t persisted_vsize =
		uint64_deserialize(d->data + 3 * sizeof(uint64_t));

	/* Value_size is arbitrary for bitsets. */
	if ((*val_type != BITSET) && (persisted_vsize != *val_size)){
		rc = D_MISMATCH_VALUE_SIZE;
		*val_size = persisted_vsize;
		goto fail_mismatch_size;
	}

	d->use = uint64_deserialize(d->data + 4 * sizeof(uint64_t));
	d->cap = uint64_deserialize(d->data + 5 * sizeof(uint64_t));
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

	rc = darray_alloc(d, 0); /* Signal darray_alloc() to map the whole file. */

	switch(rc) {
	default: /* Error in darray_alloc */
		goto fail_darray_alloc_persistance; /* TODO: Better name */
	case EMPTY_FILE:
		assert(d->data == NULL);
		return EMPTY_FILE; /* Not a failure case! */
	case SUCCESS:  /* The file has stuff. Continue. */
		break;
	}

	assert(d->data != NULL);

	if ((rc = darray_header_deserialize(d, val_type, val_size)) != SUCCESS) {
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

/* Allocates memory for the path 'dir/name.ext' */
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
	if (!(*path)) {
		rc = D_MALLOC;
		goto fail_malloc;
	}

	assert(*path != NULL);

	/* Copy over appropriate fields, with unix path conventions. */
	memcpy(*path, dir, dir_len);
	(*path)[dir_len] = '/';
	memcpy(*path + dir_len + 1, name, name_len);
	(*path)[dir_len + name_len + 1] = '.';
	memcpy(*path + dir_len + name_len + 2, ext, ext_len + 1); /* null too */

	/* Postconditions. */
	assert((*path)[dir_len + name_len + ext_len + 2] == '\0');
	return SUCCESS;

fail_malloc:
	*path = NULL;

	assert(rc != SUCCESS);
	assert(*path == NULL);
	return rc;
}

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
	/* Initialize the rest of the darray struct, using the persistent version
	 * stored on the file if needed.
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
		rc = D_WRAP;
		goto fail_alloc_size_wrap;
	}
	alloc_size += HEADER_LENGTH;

	if ((!d->data) && (rc = darray_alloc(d, alloc_size))) {
		/* Initialization failed. Short circuiting ensures no double-alloc. */
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

enum DARRAY_ERROR
darray_free(struct darray *d)
{
	/* Preconditions */
	assert(d->use <= d->cap);

	if (d->path) {
		free(d->path);
	}
	if (d->data) {
#ifndef MALLOC
		msync(d->data, d->lsize, MS_SYNC);
		munmap(d->data, d->lsize);
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

static enum DARRAY_ERROR
darray_uint8_push(struct darray *d, const void *v)
{
	/* Preconditions */
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

static void
darray_uint8_get(const struct darray *d, const size_t ind, void *v)
{
	/* Preconditions */
	assert(d->use <= d->cap);
	assert(ind <= d->use);
	assert(d->lsize >= d->cap);

	const size_t rind = ind * sizeof(uint8_t);
	const unsigned char *rdata = d->data + HEADER_LENGTH;
	assert(rind >= ind - 1);
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

	enum VALUE_TYPE t = UNSIGNED_INT;
	//enum VALUE_TYPE t = BITSET;
	size_t vs = sizeof(uint64_t);

	if ((rc = darray_init(&d, 0, &t, &vs,
		"/Users/nick/scratch/mmap_dynamic_array", "test", "eves")) != SUCCESS) {
		printf("Error: %s\n", darray_strerror(rc));
		goto fail_darray_init;
	}

	for (uint64_t i = 0; i < 10000000; ++i) {
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
