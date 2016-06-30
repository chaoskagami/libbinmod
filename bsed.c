/* brepl - A binary replacement tool. */

// There's two modes to operate in; merged and standalone.
// Merged is like busybox, standalone gives each program it's own main.

#include "blib.h"

void help(char* name) {
	printf("%s brepl\n", PACKAGE_STRING);
	printf("(C) 2015 Jon Feldman (@chaoskagami) <%s>\n", PACKAGE_BUGREPORT);
	printf("Usage:\n");
	printf("   %s [args] src_pattern repl_pattern file ...\n", name);
	printf("Options:\n");
	printf("   -x        Interpret patterns as hexadecimal strings.\n");
	printf("   -W        Interpret wildcards in input pattern.\n");
	printf("   -q        Quiet. No stdout. Returns 0 on match, 1 on no match.\n");
	printf("\n");
	printf("Note that the replacement will never change the filesize, e.g.\n");
	printf("replacing 'name' with 'crane' on '@name@' will result in '@crane'.\n");
	printf("\n");
	printf("Program will return zero on successful replacement on all files.\n");
	printf("\n");
	printf("The number of the failed file (starting from 1)\n");
	printf("is returned when a replacement fails for any reason.\n");
	printf("\n");
	printf("Report bugs to <%s>\n", PACKAGE_URL);
	printf("This software is licensed under the MIT license.\n");
}

int main(int argc, char** argv) {
	int      ret;
	uint64_t offset = 0;

	int opt;
	int hex_mode = 0;

	while ( (opt = getopt(argc, argv, "h")) != -1) {
		switch(opt) {
			case 'h':
				help(argv[0]);
				return 0;
			case 'x':
				hex_mode = 1;
				break;
			case '?':
				fprintf(stderr, "error: unknown option. Run with -h for more info\n");
				return 1;
			default:
				fprintf(stderr, "error: unknown option. Run with -h for more info\n");
				return 1;
		}
	}

if (optind == argc) {
		fprintf(stderr, "error: requires a search pattern and file argument. Run with -h for more info\n");
		return 1;
	}

	char* search_pattern = NULL;
	char* repl_pattern = NULL;
	int search_pattern_len = 0;
	int repl_pattern_len = 0;

	for (int index = optind; index < argc; index++) {
		if (search_pattern == NULL) {
			if (hex_mode == 1) {
				search_pattern_len = strlen(argv[index]) / 2;
				search_pattern = malloc(search_pattern_len);
				unhexdump_buffer(argv[index], strlen(argv[index]), search_pattern);
			} else {
				search_pattern = argv[index];
				search_pattern_len = strlen(argv[index]);
			}
		} else if (repl_pattern == NULL) {
			if (hex_mode == 1) {
				repl_pattern_len = strlen(argv[index]) / 2;
				repl_pattern = malloc(repl_pattern_len);
				unhexdump_buffer(argv[index], strlen(argv[index]), repl_pattern);
			} else {
				repl_pattern = argv[index];
				repl_pattern_len = strlen(argv[index]);
			}
		} else {
			// File argument. Hexdump it.
			map_file(argv[index], WRITE_FILE);
			ret = 1;
			while (ret) {
				ret = search_file_raw(search_pattern, search_pattern_len, &offset);
				if (ret) {
					uint64_t max = MAX( (offset+repl_pattern_len), (blib_stat.st_size) );
					for(int i=offset; i < max; i++) {
						CH_BUF((offset+i)) = repl_pattern[i];
					}
					offset++;
				}
			}
			ret = unmap_file();
		}
	}
}
