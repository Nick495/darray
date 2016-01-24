#ifndef DARRAY_XMACRO_H__
#define DARRAY_XMACRO_H__

#define sequence \
    select(SUCCESS, "No error.")\
    select(EMPTY_FILE, "The file is empty, no persistant data. No error.")\
    select(D_WRAP, "Unsigned integer wrap.")\
    select(D_STAT, "Failed to stat() given file.")\
    select(D_OPEN, "Failed to open() given file. (NOTE: permissions rw)")\
    select(D_LSEEK, "Failed to lseek() given file's given location.")\
    select(D_WRITE, "Failed to write() to the given file.")\
    select(D_CLOSE, "Failed to close() the given file.")\
    select(D_MMAP, "Failed to mmap() the given file. NOTE: permissions rw")\
    select(D_MSYNC, "Failed to msync() the given file.")\
    select(D_MUNMAP, "Failed to munmap() the given file.")\
    select(D_MALLOC, "Failed to malloc() the given file.")\
    select(D_BAD_IDENTIFIER, "The given file is corrupt or invalid.")\
    select(D_BAD_VERSION, "Cannot read given file's version.")\
    select(D_BAD_TYPE, "The given file is either corrupted or invalid.")\
    select(D_BAD_USECAP, "The given file is either corrupted or invalid.")\
    select(D_MISMATCH_TYPE, "The file's TYPE conflicts with that given.")\
    select(D_MISMATCH_VALUE_SIZE, \
            "The file's val_size conflicts with that given.")\
    select(D_BADVAL, "A bad parameter was provided.")

// Generate the enum.
#undef select
#define select(symbol, string) symbol,
enum DARRAY_ERROR { sequence };

#undef select
#define select(symbol, string) #string,
static const char * errorStrings[] = { sequence };

const char *darray_strerror(int err) {
	return errorStrings[err];
}

#endif
