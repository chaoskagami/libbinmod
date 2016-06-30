/* bgrep - A binary grep tool. */

#include "blib.h"

void help(char* name) {
	printf("%s bgrep\n", PACKAGE_STRING);
	printf("(C) 2015 Jon Feldman (@chaoskagami) <%s>\n", PACKAGE_BUGREPORT);
	printf("Usage:\n");
	printf("   %s [args] search file ...\n", name);
	printf("Options:\n");
	printf("   -x        Interpret search as hexadecimal pairs\n");
	printf("   -C BYTES  Context bytes around match (default: 8)\n");
	printf("   -H        Print filename before match\n");
	printf("   -E        Interpret search string as regex\n");
	printf("   -q        Quiet. No stdout. Returns 0 on match, 1 on no match.\n");
	printf("             All files specified must match for a success return.\n");
	printf("Report bugs to <%s>\n", PACKAGE_URL);
	printf("This software is licensed under the MIT license.\n");
}

int main(int argc, char** argv) {
	int      ret;
	uint64_t offset = 0;

	int opt;

	int hex_mode = 0;

	while ( (opt = getopt(argc, argv, "hx")) != -1) {
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

	uint8_t* search_pattern = NULL;
	int search_pattern_len = 0;

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
/*			printf("Finding '");
			for(int i=0; i < search_pattern_len; i++)
				printf("%hhx ", search_pattern[i]);
			printf("'\n");*/
		} else {
			// File argument. Hexdump it.
			map_file(argv[index], READ_FILE);
			ret = 1;
			while (ret) {
				ret = search_file_raw(search_pattern, search_pattern_len, &offset);
				if (ret) {
					printf("Match at 0x%08X\n", offset);
					offset++;
				}
			}
			ret = unmap_file();
		}
	}
}
