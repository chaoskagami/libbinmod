/* bgrep - A binary grep tool. */

#include "blib.h"

#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x20

int flip_pe_la_flag(char* name) {
	map_file(name, WRITE_FILE);

	if( CH_BUF(0) != 'M' || CH_BUF(1) != 'Z' )
		goto invalid_ret; // MZ header missing.

	uint32_t pe_loc = U32_BUF(0x3C);

	if ( U32_BUF(pe_loc) != 0x4550 )
		goto invalid_ret; // No PE header here.

	pe_loc += 0x12;
	U16_BUF(pe_loc) ^= IMAGE_FILE_LARGE_ADDRESS_AWARE; // Toggle it.

	// Succeeded
	unmap_file();
	return 0;

invalid_ret:
	unmap_file();
	return 1;
}

int check_pe_la_flag(char* name) {
	map_file(name, READ_FILE);

	if( CH_BUF(0) != 'M' || CH_BUF(1) != 'Z' )
		goto invalid_ret; // MZ header missing.

	uint32_t pe_loc = U32_BUF(0x3C);

	if ( U32_BUF(pe_loc) != 0x4550 )
		goto invalid_ret; // No PE header here.

	pe_loc += 0x12;
	if( !(U16_BUF(pe_loc) & IMAGE_FILE_LARGE_ADDRESS_AWARE) )
		goto no_ret; // Not LA aware, is PE

	// LA aware PE image.
	unmap_file();
	return 0;

no_ret:
	unmap_file();
	return 1;

invalid_ret:
	unmap_file();
	return 2;
}

int check_pe(char* name) {
	map_file(name, READ_FILE);

	if( CH_BUF(0) != 'M' || CH_BUF(1) != 'Z' )
		goto invalid_ret; // MZ header missing.

	uint32_t pe_loc = U32_BUF(0x3C);

	if ( U32_BUF(pe_loc) != 0x4550 )
		goto invalid_ret; // No PE header here.

	unmap_file();
	return 0; // Is PE

invalid_ret:
	unmap_file();
	return 1; // Not PE
}


void help(char* name) {
	printf("%s bflag\n", PACKAGE_STRING);
	printf("(C) 2015 Jon Feldman (@chaoskagami) <%s>\n", PACKAGE_BUGREPORT);
	printf("Usage:\n");
	printf("   %s [args] file ...\n", name);
	printf("Options (PE Images):\n");
	printf("   -v        Show information on file\n");
	printf("   -L        Flip the large address aware bit\n");
	printf("Report bugs to <%s>\n", PACKAGE_URL);
	printf("This software is licensed under the MIT license.\n");
}

int main(int argc, char** argv) {
	int opt;

	int do_op = 0;

	while ( (opt = getopt(argc, argv, "hvL")) != -1) {
		switch(opt) {
			case 'h':
				help(argv[0]);
				return 0;
				break;
			case 'v':
				do_op = 1; // View
				break;
			case 'L':
				do_op = 2; // Flip LA flag
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

	int ret = 0;

	switch(do_op) {
		case 0:
			fprintf(stderr, "error: no operation specified\n");
			return 1;
		case 1: // View flags
			printf("Is PE Image: ");
			ret = check_pe(argv[optind]);

			if (ret == 0) {
				printf("Yes\n");

				printf("Large Address Aware: ");

				ret = check_pe_la_flag(argv[optind]);

				if (ret == 0) {
					printf("Yes\n");
				} else {
					printf("No\n");
				}
			} else {
				printf("No\n");
			}

			break;
		case 2:
			ret = flip_pe_la_flag(argv[optind]);
			if (ret == 0)
				printf("Flipped the LA bit.\n");
			else
				printf("Failed to flip LA bit.\n");

			break;
	}

}
