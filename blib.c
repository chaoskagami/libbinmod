#define BLIB_NO_EXTERNS

#include "blib.h"

int            blib_filefd;
unsigned char* blib_buffer;
struct stat    blib_stat;
int            open_flags;
int            mmap_flags;

int copy_file(__READ const char* dest, __READ const char* src) {
	// We use the generic POSIX way.

	int in_fd = open(src, O_RDONLY);
	if(in_fd <= 0)
		goto error_copy_file;

	int out_fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (out_fd <= 0)
		goto error_copy_file;

	char buf[8192];

	while (1) {
		ssize_t result = read(in_fd, buf, sizeof(buf));

		if (!result) // Done?
			break;

		if(result < 0) {
			// ERROR!
			fprintf(stderr, "Negative bytes read?\n");
			goto error_copy_file;
		}

		if (write(out_fd, buf, result) != result) {
			// Short write? Out of disk, maybe. Either way, abort.
			fprintf(stderr, "Short write?\n");
			goto error_copy_file;
		}
	}

	close(in_fd);
	close(out_fd);

	return 0;

error_copy_file:
	if (in_fd) close(in_fd);
	if (out_fd) close(out_fd);

	return 1;
}

// Loads up a file. 0 on success, 1 on error.
int map_file(__READ const char* name,
             __READ const int mode)
{
	open_flags = 0;
	mmap_flags = 0;

	if (mode == READ_FILE) {
		open_flags = O_RDONLY;
		mmap_flags = PROT_READ;
	}
	else if (mode == WRITE_FILE) {
		open_flags = O_RDWR;
		mmap_flags = PROT_READ | PROT_WRITE;
	}

    blib_filefd = open(name, open_flags);
    if (blib_filefd == -1) {
		perror("Error opening file for reading");
		exit(EXIT_FAILURE);
    }

	int status = fstat(blib_filefd, &blib_stat);

    blib_buffer = mmap(0, blib_stat.st_size, mmap_flags, MAP_SHARED, blib_filefd, 0);
    if (blib_buffer == MAP_FAILED) {
		close(blib_filefd);
		perror("Error mmapping the file");
		exit(EXIT_FAILURE);
    }

    return 0;
}

// Loads up a file. 0 on success, 1 on error.
// Note that it must be opened write.
int map_file_expand(__READ const char* name,
                    __READ const uint32_t expand)
{
	open_flags = O_RDWR;
	mmap_flags = PROT_READ | PROT_WRITE;

    blib_filefd = open(name, open_flags);
    if (blib_filefd == -1) {
		perror("Error opening file for reading");
		exit(EXIT_FAILURE);
    }

	int status = fstat(blib_filefd, &blib_stat);

	// Check size and expand.
	if (blib_stat.st_size < expand) {
		// Smaller than write. Expand.
		ftruncate(blib_filefd, expand);
		// Re-read stat.
		int status = fstat(blib_filefd, &blib_stat);
	}

    blib_buffer = mmap(0, blib_stat.st_size, mmap_flags, MAP_SHARED, blib_filefd, 0);
    if (blib_buffer == MAP_FAILED) {
		close(blib_filefd);
		perror("Error mmapping the file");
		exit(EXIT_FAILURE);
    }

    return 0;
}

// Unloads the file.
int unmap_file() {
	if (mmap_flags == PROT_READ | PROT_WRITE) {
		// Sync it to disk.
		msync(blib_buffer, blib_stat.st_size, MS_SYNC);
	}

	if (munmap(blib_buffer, blib_stat.st_size) == -1) {
		perror("Error un-mmapping the file");
	}
	close(blib_filefd);
}

// Searches for a pattern. Returns 1 on match with offset stored to
// 'offset'. Returns 0 on EOF/no more matches.
int search_file_raw(__READ const unsigned char* pattern,
					__READ const int pattern_len,
                    __WRITE uint64_t* offset)
{
	for(uint64_t i = *offset; i < blib_stat.st_size; i++) { // mmap offset
		int ret = memcmp(blib_buffer+i, pattern, pattern_len);
		if (ret == 0) {
			*offset = i;
			return 1;
		}
	}
	return 0;
}

int hexdump_file(__READ uint64_t offset, __READ uint64_t len, __READ int format) {

	if (offset > blib_stat.st_size) {
		// Invalid. Exit.
		return 0;
	} else if (offset + len > blib_stat.st_size) {
		// Length is too long. Return the amount to correct it.
		return blib_stat.st_size - (offset+len);
	}

	return hexdump_manual(offset, blib_buffer, len, format, stdout);
}

int hexdump_manual(__READ uint64_t offset, __READ uint8_t* buffer, __READ uint64_t len, __READ int format, FILE* output) {
	// Okay, hexdump.

	for (int i = 0; i < len;) {
		int length = 16;
		if (len - i < 16) // Incomplete line.
			length = len - i;

		// First, offsets.
		if (format & PRINT_OFFSET) {

			fprintf(output, "%08x", i);

			if (format & USE_COLON)
				fprintf(output, ":");
			else if (format & PIPE_OFFSET)
				fprintf(output, " | ");
			else
				fprintf(output, " ");
			fprintf(output, " ");
		}

		// Next, bytes.
		if (format & BYTE_A) { // One byte
			int copylen = length;
			for(int j=0; j < 16; j++) {
				if (copylen) {
					fprintf(output, "%02x ", buffer[i+j]);
					copylen--;
				} else {
					fprintf(output, "   ");
				}
				if (j == 7 && (format & CENTER_SPLIT) )
					fprintf(output, " ");
			}
		} else if (format & BYTE_B) { // Two byte
			int copylen = length;
			for(int j=0; j < 16; j++) {
				if (copylen) {
					fprintf(output, "%02x", buffer[i+j]);
					if (j % 2 == 1)
						fprintf(output, " ");
					copylen--;
				} else {
					fprintf(output, "  ");
					if (j % 2 == 1)
						fprintf(output, " ");
				}
				if (j == 7 && (format & CENTER_SPLIT) )
					fprintf(output, " ");
			}
		} else if (format & BYTE_C) { // Three byte
			int copylen = length;
			for(int j=0; j < 16; j++) {
				if (copylen) {
					fprintf(output, "%02x", buffer[i+j]);
					if (j % 4 == 3)
						fprintf(output, " ");
					copylen--;
				} else {
					fprintf(output, "  ");
					if (j % 4 == 3)
						fprintf(output, " ");
				}
				if (j == 7 && (format & CENTER_SPLIT) )
					fprintf(output, " ");
			}
		}

		if (format & WITH_ASCII) { // Print ascii
			fprintf(output, " ");

			if (format & PIPE_SEPARATE) {
				fprintf(output, "|");
			}

			for(int j=0; j < length; j++) {
				// We only print printables.
				int c = buffer[i+j];
				if (c > 0x1f && c < 0x7f) // Printable?
					fprintf(output, "%c", c);
				else {
					if (format & NONPRINT_PERIOD) {
						fprintf(output, ".");
					} else if (format & NONPRINT_UNDERS) {
						fprintf(output, "_");
					} else {
						fprintf(output, " ");
					}
				}
			}

			if (format & PIPE_SEPARATE) {
				fprintf(output, "|");
			}
		}

		i += 16;
		fprintf(output, "\n");
	}
}

uint8_t hexb_to_u8(char a, char b) {
	if (a >= 'a' && a <= 'f') {
		a -= 'a';
		a += 10;
	} else if (a >= 'A' && a <= 'F') {
		a -= 'A';
		a += 10;
	} else if (a >= '0' && a <= '9') {
		a -= '0';
	} else {
		return 0;
	}

	if (b >= 'a' && b <= 'f') {
		b -= 'a';
		b += 10;
	} else if (b >= 'A' && b <= 'F') {
		b -= 'A';
		b += 10;
	} else if (b >= '0' && b <= '9') {
		b -= '0';
	} else {
		return 0;
	}

	return ((a<<4)|b);
}

// Unhexdump
int unhexdump_buffer(__READ uint8_t* buffer, __READ uint64_t len, __WRITE uint8_t* output) {
	for(int i=0; i < (len/2); i++) {
		output[i] = hexb_to_u8(buffer[i*2], buffer[i*2+1]);
	}
}
