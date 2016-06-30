/* bxxd - A binary hexdump tool. */

#include "blib.h"

// Parameters:
//   -C canonical / coreutils hexdump
//   -X xxd / vim xxd format
//   -F Fancy mode, colorized
//   -f Fancy mode, no color.

void help(char* name) {
	printf("%s bxxd\n", PACKAGE_STRING);
	printf("(C) 2015 Jon Feldman (@chaoskagami) <%s>\n", PACKAGE_BUGREPORT);
	printf("Usage:\n");
	printf("   %s [args] file ...\n", name);
	printf("Options:\n");
	printf("   -C        Canonical / 'hexdump -C' emulation (color)\n");
	printf("   -c        Canonical / 'hexdump -C' emulation\n");
	printf("   -X        vim 'xxd' emulation (color)\n");
	printf("   -x        vim 'xxd' emulation\n");
	printf("   -F        Fancy (color)\n");
	printf("   -f        Fancy\n");
	printf("Report bugs to <%s>\n", PACKAGE_URL);
	printf("This software is licensed under the MIT license.\n");
}

int main(int argc, char* argv[]) {
	int      ret;
	uint64_t offset = 0;
	int mode = SPACED_BYTES;
	int opt;

	while ( (opt = getopt(argc, argv, "hCcXxFf")) != -1) {
		switch(opt) {
			case 'h':
				help(argv[0]);
				return 0;
				break;
			case 'C':
				mode = PRESET_HEXDUMP_C | COLORIZED;
				break;
			case 'c':
				mode = PRESET_HEXDUMP_C;
				break;
			case 'X':
				mode = PRESET_XXD | COLORIZED;
				break;
			case 'x':
				mode = PRESET_XXD;
				break;
			case 'F':
				mode = PRESET_FANCY | COLORIZED;
				break;
			case 'f':
				mode = PRESET_FANCY;
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
		fprintf(stderr, "error: requires a file argument. Run with -h for more info\n");
		return 1;
	}

	for (int index = optind; index < argc; index++) {
		// File argument. Hexdump it.
		ret = map_file(argv[index], READ_FILE);
		ret = hexdump_file(0, blib_stat.st_size, mode);
		ret = unmap_file();
	}

	return 0;
}
