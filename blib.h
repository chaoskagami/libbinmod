/* Common functions for binary modifying programs. */

#ifndef __BINLIB_H
#define __BINLIB_H

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <unistd.h>

#include "config.h"

#ifdef MAX
#undef MAX
#endif
#define MAX(a,b) \
  ({ __typeof__ (a) _a = (a); \
     __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#ifndef BLIB_NO_EXTERNS
  // No externs in blib.c.
  extern unsigned char* blib_buffer;
  extern struct stat    blib_stat;
#endif

#define U32_BUF(x) (((uint32_t*)(&blib_buffer[x]))[0])
#define U16_BUF(x) (((uint16_t*)(&blib_buffer[x]))[0])
#define CH_BUF(x)  blib_buffer[x]

// map_file flags
#define READ_FILE  0
#define WRITE_FILE 1 // Implies read

// Hexdump feature bits
#define USE_SPACES      1
#define PRINT_OFFSET    2
#define USE_COLON       4
#define LINE_BREAKS     8
#define PIPE_SEPARATE   16
#define PIPE_OFFSET     32
#define WITH_ASCII      64
#define BYTE_A          128  // 1byte
#define BYTE_B          256  // 2byte
#define BYTE_C          512  // 4byte
#define CENTER_SPLIT    1024
#define NONPRINT_PERIOD 2048
#define NONPRINT_UNDERS 4096
#define COLORIZED       8192

// Hexdump presets.
#define SPACED_BYTES       USE_SPACES | BYTE_A
#define PRESET_XXD         USE_SPACES | BYTE_B | PRINT_OFFSET | USE_COLON | WITH_ASCII | LINE_BREAKS | NONPRINT_PERIOD
#define PRESET_HEXDUMP_C   USE_SPACES | BYTE_A | PRINT_OFFSET | PIPE_SEPARATE | WITH_ASCII | LINE_BREAKS | CENTER_SPLIT | NONPRINT_PERIOD
#define PRESET_FANCY       USE_SPACES | BYTE_A | PRINT_OFFSET | PIPE_SEPARATE | WITH_ASCII | LINE_BREAKS | CENTER_SPLIT | PIPE_OFFSET

// None of these have any meaning, but serve as documentation.
#define __WRITE
#define __READ
#define __WRITEREAD

// Buffer size.
#define BUFFER_SIZE 1024

// Loads up a file. 0 on success, 1 on error.
int map_file(__READ const char* name,
             __READ const int mode);

// Loads up a file, expanding first if needed.
int map_file_expand(__READ const char* name,
                    __READ const uint32_t expand);

// Unmap and sync file.
int unmap_file();

// Copy file.
int copy_file(__READ const char* dest, __READ const char* src);

// Searches for a pattern. Returns 1 on match with offset stored to
// 'offset'. Returns 0 on EOF/no more matches.

int search_file_raw(__READ const unsigned char* pattern,
					__READ const int pattern_len,
                    __WRITE uint64_t* offset);

// Hexdump
int hexdump_file(__READ uint64_t offset, __READ uint64_t len, __READ int format);
int hexdump_manual(__READ uint64_t offset, __READ uint8_t* buffer, __READ uint64_t len, __READ int format, FILE* output);

// Unhexdump
int unhexdump_buffer(__READ uint8_t* buffer, __READ uint64_t len, __WRITE uint8_t* output);

#endif
