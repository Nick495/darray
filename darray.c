#include <stdlib.h>
#include <assert.h>
#include <sys/mman.h>
#include <string.h> /* strlen(), memcpy() */
#include <fcntl.h>	/* open() */
#include <unistd.h>	/* close() */
#include <sys/stat.h> /* struct stat, stat() */

#include <stdio.h> /* DEBUG */

struct darray;

typedef int (*push_func)(struct darray *, const void *);
typedef void (*get_func)(const struct darray *, const size_t, void *);

enum TYPE {UNSIGNED_INT, BITSET};
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
 * TODO: Implement persistance.
 *
 * TODO: Finalize error handling.
 *
 * TODO: Double check with someone else that the bitarray is being used properly
*/
struct darray {
	uint64_t use;
	uint64_t cap;
	uint64_t dsize; /* Size of serialized darray, doesn't vary with arch*/
	int fd;
	char *path;
	unsigned char *data;
	push_func push;
	get_func get;
};

static int darray_extend_file(struct darray *d, const size_t new_alloc)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->path != NULL);

	int rc = 0;
	const int fd = open(d->path, O_RDWR|O_CREAT|O_NOFOLLOW);
	if (fd < 0) {
		rc = -1;
		goto fail_open;
	}

	if (lseek(fd, new_alloc, SEEK_SET) == -1) {
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

static int darray_alloc_array(struct darray *d, const size_t alloc_size)
{
	/* Preconditions */
	assert(d != NULL);
	assert(d->path != NULL);
	assert(d->use >= 0);
	assert(alloc_size > d->dsize);

	int rc = 0; 

#ifdef MALLOC
	void *new_data = realloc(d->data, alloc_size);
	if (!new_data) {
		rc = 1;
		goto fail_darray_extend;
	}
	assert(new_data != NULL);
#else
	struct stat statb;
	/* TODO: Change the below code to continue on if the stat() error is that
	 * the file isn't found so that it can be created instead. Basically all
	 * that needs to happen is statb.st_size needs to be set to zero.
	*/
	if ((rc = stat(d->path, &statb))) {
		rc = 2;
		goto fail_stat;
	}

	int fd;
	if ((statb.st_size < (off_t)alloc_size)) { /* Extend the file. */
		if ((fd = darray_extend_file(d, alloc_size)) < 0) {
			rc = 3;
			goto fail_extend_file;
		}
	} else { /* Otherwise just open it. */
		if ((fd = open(d->path, O_RDWR|O_NOFOLLOW)) < 0) {
			rc = 4;
			goto fail_open;
		}
	}
	assert(fd > 0);

	void *new_data
		= mmap(0, alloc_size, PROT_READ|PROT_WRITE, MAP_FILE|MAP_SHARED, fd, 0);
	if (!new_data) {
		rc = 5;
		goto fail_mmap;
	}
	assert(new_data != NULL);

	if (close(fd) == -1) {
		rc = 6;
		goto fail_close;
	}
#endif
	d->data = new_data;

	/* Post conditions */
	assert(d->data != NULL);
	return 0;

#ifdef MALLOC
	free(new_data);
fail_darray_extend:
#else
fail_close:
	munmap(new_data, alloc_size);
fail_mmap:
	close(fd);
fail_open:
fail_extend_file:
fail_stat:
#endif
	assert(rc != 0);
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

	if ((rc = darray_alloc_array(d, new_size))) {
		rc += 1; /* Don't clobber existing error codes. */
		goto fail_darray_alloc_array;
	}

	assert(d->data != NULL);
	d->cap = new_cap;
	d->dsize = new_size;

	/* Post_conditions. */
	assert(d->data != NULL);
	assert(d->dsize > 0);
	assert(d->use < d->cap);
	return 0;

fail_darray_alloc_array:
fail_int_overflow:
	assert(rc != 0);
	return rc;
}

/* Note: I'm not sure if I need to check these functions for wrap on size_t,
 * since there is multiplication with d->use, but I think they're protected by
 * constraints with d->dsize. As of now it's protected by an assert().
*/
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
	memcpy(&d->data[rind], v, sizeof(uint8_t));
#else
	d->data[rind + 0] = (*((const uint8_t *) v) >> 0);
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
	memcpy(v, &d->data[rind], sizeof(uint8_t));
#else
	*((uint8_t *)v) = ((uint8_t)d->data[rind] << 0);
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
	memcpy(&d->data[rind], v, sizeof(uint16_t));
#else
	d->data[rind + 0] = (*((const uint16_t *) v) >> 8);
	d->data[rind + 1] = (*((const uint16_t *) v) >> 0);
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
	memcpy(v, &d->data[rind], sizeof(uint16_t));
#else
	*((uint16_t *)v) =
		(((uint16_t)d->data[rind] << 8) | ((uint16_t)d->data[rind+1] << 0));
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
	memcpy(&d->data[rind], v, sizeof(uint32_t));
#else
	d->data[rind + 0] = (*((const uint32_t *) v) >> 24);
	d->data[rind + 1] = (*((const uint32_t *) v) >> 16);
	d->data[rind + 2] = (*((const uint32_t *) v) >> 8);
	d->data[rind + 3] = (*((const uint32_t *) v) >> 0);
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
	memcpy(v, &d->data[rind], sizeof(uint32_t));
#else
	*((uint32_t *)v) =
		(((uint32_t)d->data[rind] << 24) | ((uint32_t)d->data[rind+1] << 16) |
		((uint32_t)d->data[rind+2] << 8) | ((uint32_t)d->data[rind+3] << 0));
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
	memcpy(&d->data[rind], v, sizeof(uint64_t));
#else
	d->data[rind + 0] = (*((const uint64_t *) v) >> 56);
	d->data[rind + 1] = (*((const uint64_t *) v) >> 48);
	d->data[rind + 2] = (*((const uint64_t *) v) >> 40);
	d->data[rind + 3] = (*((const uint64_t *) v) >> 32);
	d->data[rind + 4] = (*((const uint64_t *) v) >> 24);
	d->data[rind + 5] = (*((const uint64_t *) v) >> 16);
	d->data[rind + 6] = (*((const uint64_t *) v) >> 8);
	d->data[rind + 7] = (*((const uint64_t *) v) >> 0);
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
	memcpy(v, &d->data[rind], sizeof(uint64_t));
#else
	*((uint64_t *)v) =
		(((uint64_t)d->data[rind] << 56) | ((uint64_t)d->data[rind+1] << 48) |
		((uint64_t)d->data[rind+2] << 40) | ((uint64_t)d->data[rind+3] << 32) |
		((uint64_t)d->data[rind+4] << 24) | ((uint64_t)d->data[rind+5] << 16) |
		((uint64_t)d->data[rind+6] << 8) | ((uint64_t)d->data[rind+7] << 0));
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

	if ((*(const unsigned int *)v)) {
		d->data[rind] |= (1 << roff);
	} else {
		d->data[rind] &= ~(1 << roff);
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

	*((unsigned int *) v) = d->data[rind] & (1 << roff);
	return;
}

int darray_init(struct darray *d, const enum TYPE val_type,
		const size_t init_size, const size_t val_size,
		const char *dir, const char *name, const char *ext)
{
	/* Preconditions */
	assert(d != NULL);
	assert(init_size >= 0);
	assert(val_size > 0);
	assert(dir != NULL);
	assert(name != NULL);
	assert(ext != NULL);

	const size_t dir_len = strlen(dir);
	const size_t name_len = strlen(name);
	const size_t ext_len = strlen(ext);

	int rc = 0;
	d->use = 0;
	d->cap = (init_size == 0) ? 5 : init_size;
	d->dsize = 0;
    d->data = NULL;
    d->path = NULL;
    d->push = NULL;
    d->get = NULL;

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

	/* Lame polymorphism */
	size_t alloc_size = 0;
	switch(val_type) {
	case UNSIGNED_INT: {
		switch(val_size) {
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

		alloc_size = d->cap * val_size;
		if (alloc_size <= d->cap) {
			rc = 2;
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
		*/
		alloc_size =(sizeof(uint64_t)-1 + d->cap/sizeof(uint64_t));
		break;
	}
	}
	assert(d->push != NULL);
	assert(d->get != NULL);
	assert(alloc_size > 0);

	if ((rc = darray_alloc_array(d, alloc_size))) {
		rc += 2; /* Don't duplicate previous error codes. */
		goto fail_darray_alloc_array;
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

fail_darray_alloc_array:
fail_dsize_overflow:
	free(d->path);
fail_path_malloc:
	assert(rc != 0);
	return rc;
}

void darray_free(struct darray *d)
{
	/* Preconditions */
	assert(d->use <= d->cap);
	assert(d->dsize >= d->cap);

	free(d->path);
#ifdef MALLOC
	free(d->data);
#else
	msync(d->data, d->dsize, MS_SYNC);
	munmap(d->data, d->dsize);
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

#include <stdio.h>
void darray_uint_print_all(struct darray *d)
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

void darray_bset_print_all(struct darray *d)
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

	const enum TYPE t = UNSIGNED_INT;
	//const enum TYPE t = BITSET;

	if ((rc = darray_init(&d, t, 0, sizeof(uint64_t),
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
