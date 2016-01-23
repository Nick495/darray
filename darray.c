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
	int fd;
	size_t dsize;
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
static int darray_stretch_size(struct darray *d, const size_t alloc_size)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->path != NULL);
	assert(alloc_size > 0);

	int rc = 0;
	const int fd = open(d->path, O_RDWR|O_CREAT|O_NOFOLLOW);
	if (fd < 0) {
		rc = -1;
		goto fail_open;
	}

	if (lseek(fd, alloc_size, SEEK_SET) == -1) {
		rc = -2;
		goto fail_lseek;
	}

	if (write(fd, "", 1) == -1) {
		rc = -3;
		goto fail_write;
	}

	assert(fd >= 0);
	return fd;

fail_write:
fail_lseek:
	close(fd);
fail_open:
	assert(rc != 0);
	return rc;
}
#endif

static int darray_alloc(struct darray *d, size_t alloc_size)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->path != NULL);
	assert(d->use >= 0);

	int rc = 0; 

#ifndef MALLOC
	struct stat statb;
	/* TODO: Change the below code to continue on if the stat() error is that
	 * the file isn't found so that it can be created instead. Basically all
	 * that needs to happen is statb.st_size needs to be set to zero.
	*/
	if ((rc = stat(d->path, &statb))) {
		rc = -1;
		goto fail_stat;
	}

	int fd;
	/* Special case, darray_init() is looking for a serialized darray */
	if (alloc_size == 0) {
		if (statb.st_size == 0) { /* Nothing here, report back. */
			return 1;
		} else { /* Map it as is */
			if ((fd = open(d->path, O_RDWR|O_NOFOLLOW)) < 0) {
				rc = -2;
				goto fail_open;
			}
			/* Note, the line below is the critical difference between this case
			 * and the more general case where alloc_size <= statb.st_size. The
			 * rest of the code implicitly assumes that d->cap is proportional
			 * to d->dsize. (i.e. ensure_size)
			 * This line would break that assumption in general, and therefore
			 * cause the file to grow much more rapidly than is prudent. Until
			 * the code is refactored (which would involve making this function 
			 * value_size aware and having it literally compute the d->cap field
			 * to ensure that the property is retained) these two cases can't be
			 * merged. 
			*/
			alloc_size = statb.st_size;
		}
	} else { /* Standard case. */
		if (alloc_size <= (size_t)statb.st_size) {
			/* The file is big enough, so map it as is */
			if ((fd = open(d->path, O_RDWR|O_NOFOLLOW)) < 0) {
				rc = -2;
				goto fail_open;
			}
		} else {
			/* Extend the file as needed */
			if ((fd = darray_stretch_size(d, alloc_size)) < 0) {
				rc = -3;
				goto fail_extend_file;
			}
		} 
	}
	assert(fd > 0);

	void *new_data
		= mmap(0, alloc_size, PROT_READ|PROT_WRITE, MAP_FILE|MAP_SHARED, fd, 0);
	if (!new_data) {
		rc = -4;
		goto fail_mmap;
	}

	if (close(fd) == -1) {
		rc = -5;
		goto fail_close;
	}
#else
	void *new_data = realloc(d->data, alloc_size);
	if (!new_data) {
		rc = -6;
		goto fail_darray_extend;
	}
#endif

	assert(new_data != NULL);
	d->data = new_data;
	d->dsize = alloc_size;

	/* Post conditions */
	assert(d->data != NULL);
	return 0;

#ifndef MALLOC
fail_close:
	munmap(new_data, alloc_size);
fail_mmap:
	close(fd);
fail_open:
fail_extend_file:
fail_stat:
#else
	free(new_data);
fail_darray_extend:
#endif
	assert(rc < 0);
	return rc;
}

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
	const size_t new_size = d->dsize * expn_factor;
	const size_t new_cap = d->cap * expn_factor;
	if ((new_size < d->dsize) || (new_cap < d->cap)) {
		rc = 1;
		goto fail_int_overflow;
	}
	assert(new_size > d->dsize);
	assert(new_cap > d->cap);

	if ((rc = darray_alloc(d, new_size))) {
		goto fail_darray_alloc;
	}

	assert(d->data != NULL);
	d->cap = new_cap;

	/* Post_conditions. */
	assert(d->data != NULL);
	assert(d->dsize > 0);
	assert(d->use < d->cap);
	return 0;

fail_darray_alloc:
fail_int_overflow:
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

	const size_t dir_len = strlen(dir);
	const size_t name_len = strlen(name);
	const size_t ext_len = strlen(ext);

	int rc = 0;

	d->path = malloc(dir_len + name_len + ext_len + 3); /* Null terminator */
	if (!d->path) {
		rc = 1;
		goto fail_path_malloc;
	}
	assert(d->path != NULL); /* Psuedo precondition for below. */

	/* Copy over appropriate fields, with unix path conventions. */
	memcpy(d->path, dir, dir_len);
	d->path[dir_len] = '/';
	memcpy(d->path + dir_len + 1, name, name_len);
	d->path[dir_len + name_len + 1] = '.';
	memcpy(d->path + dir_len + name_len + 2, ext, ext_len + 1);/* null too */

	/* Psuedo postcondition for above. */
	assert(d->path[dir_len + name_len + ext_len + 2] == '\0');

	/* Initialize the rest of the darray struct, using the persistent version
	 * stored on the file if needed.
	*/
#ifndef MALLOC
	assert(d->path != NULL);
	rc = darray_alloc(d, 0); /* Signal darray_alloc() to map the entire file. */
	switch(rc) {
	default: /* Error in darray_alloc */
		d->data = NULL;
		goto fail_darray_alloc;
		break;
	case 1: { /* The file is empty. */
		d->use = 0;
		d->cap = (val_cnt == 0) ? 5 : val_cnt;
		d->dsize = 0;
    	d->data = NULL;
    	d->push = NULL;
    	d->get = NULL;
		break;
	}
	case 0: /* fallthru TODO: Edit darray_alloc() to differentiate
			   these cases */
	case 2: { /* The file has stuff. Check it out. */
		if ((uint64_deserialize(d->data) != 0xDEADBEEFCAFED00D)) {
			if (uint64_deserialize(d->data + sizeof(uint64_t)) > 0) {
				/* We can't read files of this version. */
				rc = 2;
				goto fail_version;
			} else {
				/* Bad file identifier. */
				rc = 3;
				goto fail_file;
			}
		}	
		/* Now we have to deseriailze the type and val_size, confirm that
		 * they're the same as the user requested, set up the remaining fields,
		 * and continue execution.
		*/
		const uint64_t encoded_value_type =
			uint64_deserialize(d->data + 2 * sizeof(uint64_t));
		const uint64_t persistent_value_size =
			uint64_deserialize(d->data + 3 * sizeof(uint64_t));
		enum VALUE_TYPE de_serial_type;
		switch(encoded_value_type) {
		case 0:
			de_serial_type = UNSIGNED_INT;
			break;
		case 1:
			de_serial_type = BITSET;
			break;
		default:
			rc = 4;
			goto fail_value_type;
			break;
		}
		if (de_serial_type != *val_type) {
			*val_type = de_serial_type;
			rc = 5;
			goto fail_value_type;
		}
		if ((de_serial_type != BITSET)&&(persistent_value_size != *val_size)){
			*val_size = persistent_value_size;
			rc = 6;
			goto fail_value_size;
		}
		d->use = uint64_deserialize(d->data + 4 * sizeof(uint64_t));
		d->cap = uint64_deserialize(d->data + 5 * sizeof(uint64_t));
		assert(d->cap >= d->use); /* TODO: change to proper error handling */
		break;
	}
	}
#else
	d->use = 0;
	d->cap = (val_cnt == 0) ? 5 : val_cnt;
	d->dsize = 0;
	d->data = NULL;
	d->push = NULL;
	d->get = NULL;
#endif

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
			goto fail_dsize_overflow;
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
		* arch with a small wordsize (e.g. 16 bits) on an arch with a bigger
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

	if (!d->data) { /* Our attempt to deserialize it from the file failed. */
		if ((rc = darray_alloc(d, alloc_size))) {
			goto fail_darray_alloc;
		}
	}
	assert(d->data != NULL);
	d->dsize = alloc_size;

	/* Post-conditions */
	assert(d->cap != 0);
	assert(d->use <= d->cap);
	assert(rc == 0);
	assert(d->data != NULL);
	assert(d->path != NULL);
	assert(d->push != NULL);
	assert(d->get != NULL);
	return 0;

fail_value_type:
fail_value_size:
fail_alloc_size_wrap:
#ifndef MALLOC
fail_file:
fail_version:
	munmap(d->data, d->dsize);
	d->data = NULL;
#else
	free(d->data);
	d->data = NULL;
#endif
fail_darray_alloc:
fail_dsize_overflow:
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
	assert(d->dsize >= d->cap);

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

	msync(d->data, d->dsize, MS_SYNC);
	munmap(d->data, d->dsize);
#else
	free(d->data);
#endif
	d->use = d->cap = d->dsize = 0;
	d->data = NULL;
	d->path = NULL;

	/* Post conditions */
	assert(d->path == NULL);
	assert(d->data == NULL);
	assert(d->use == 0);
	assert(d->cap == 0);
	assert(d->dsize == 0);
	assert(d->use <= d->cap);
}

static int darray_uint8_push(struct darray *d, const void *v)
{
	/* Preconditions */
	assert(d->use <= d->cap);
	assert(d->dsize >= d->cap);

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
	assert(d->dsize >= d->cap);

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
	assert(d->dsize >= d->cap);

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
	assert(d->dsize >= d->cap);

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
	assert(d->dsize >= d->cap);

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
	assert(d->dsize >= d->cap);

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
	assert(d->dsize >= d->cap);

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
	assert(d->dsize >= d->cap);

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
			"/Users/nick/scratch/mmap_dynamic_array", "test", "eves"))) {
		printf("Error. %d\n", rc);
		goto fail_darray_init;
	}

#if 0
	for (uint64_t i = 0; i < 10000000; ++i) {
		if ((rc = d.push(&d, &i))) {
			printf("Error, malloc.\n");
			goto fail_darray_append;
		}
	}
#endif

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
