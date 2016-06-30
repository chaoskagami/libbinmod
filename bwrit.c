/* bwrit - Writes values into files. */

#include "blib.h"

void help(char* name) {
	printf("%s brepl\n", PACKAGE_STRING);
	printf("(C) 2015 Jon Feldman (@chaoskagami) <%s>\n", PACKAGE_BUGREPORT);
	printf("Usage:\n");
	printf("   %s [args] file writes ...\n", name);
	printf("Options:\n");
	printf("   -h        Print this message.\n");
	printf("\n");
	printf("Writes should be specified in hexadecimal and of the format:\n");
	printf("   <offset>:<bytes>'\n");
	printf("\n");
	printf("Report bugs to <%s>\n", PACKAGE_URL);
	printf("This software is licensed under the MIT license.\n");
}

// Example: ac543:ff means write one byte, ff to offset ac543

int main(int c, char** v) {
	if (c >= 2 && !strcmp(v[1], "-h")) {
		help(v[0]);
		return 0;
	} else if (c < 3) {
		printf("error: not enough arguments. Run `%s -h` for more info.\n", v[0]);
		return 1;
	}

	map_file(v[1], WRITE_FILE);

	for(int i=2; i<c; i++) {
		char* offset_str = strdup(v[i]);
		char* inject_str = offset_str;
		while(*inject_str != ':' && inject_str != 0 && inject_str++); // Find ':'
		if (*inject_str == 0 || inject_str == offset_str) {
			printf("Improperly separated pattern.\n");
			unmap_file();
			return 1;
		}

		*(inject_str) = 0;
		inject_str++;

		printf("off:%s\ninj:%s\n", offset_str, inject_str);

		uint32_t loc = 0;

		sscanf(offset_str, "%x", &loc);

		unhexdump_buffer(inject_str, strlen(inject_str), & CH_BUF(loc)); // We just unhexdump straight to the destination. It's easier.
	}

	unmap_file();

	return 0;
}
