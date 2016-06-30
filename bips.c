/* bips - A IPS patcher tool */

#include "blib.h"
#include "ips_fmt.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

uint8_t* ips_buffer = NULL;

int simulate  = 0; // Don't actually apply; only show the results.
int plaintext = 0; // Decompile IPS to a human-readable listing.
int splitmini = 0; // Split IPS to one chunk mini-ips patches in a folder.

// On success, returns the number of IPS records read. On failure,
// returns -1.
int load_ips(__READ char* ips_filename, __WRITE ips_record_t** ips_structs) {
	// We load the entire thing to memory.

	FILE* f = fopen(ips_filename, "r");
	fseek(f, 0, SEEK_END);
	uint64_t pos = ftell(f);
	rewind(f);

	ips_buffer = (uint8_t*)malloc(pos);

	fread(ips_buffer, 1, pos, f);

	fclose(f);

	printf("Loaded file to memory successfully. Size: %lld\n", pos);

	// Loaded. Begin by checking shit.
	if( strncmp(ips_buffer, IPS_MAGIC, IPS_MAGIC_LENGTH) ) {
		// Invalid signature. Not an IPS.
		free(ips_buffer);
		ips_buffer = NULL;
		return -1;
	}

	// Seems legit. Begin record calculation.
	int ips_count = 0;
	uint64_t offset_in = 5;
	ips_record_t* ips_data = NULL;
	while( offset_in < pos && strncmp((char*)&ips_buffer[offset_in], IPS_TAIL, IPS_TAIL_LENGTH) ) {
		// Increment.
		ips_count++;

		// Reallocate.
		ips_data = (ips_record_t*)realloc(ips_data, sizeof(ips_record_t) * ips_count);

		ips_data[ips_count-1].info = (ips_record_com_t*)&ips_buffer[offset_in];

		offset_in += sizeof(ips_record_com_t);

		ips_data[ips_count-1].data = (void*)&ips_buffer[offset_in];

		if(ips_data[ips_count-1].info->size[0] == 0x00 && ips_data[ips_count-1].info->size[1] == 0x00) { // Zero is zero regardless of byte order, no casting needed
			// RLE. Add the size of an RLE struct.
			offset_in += sizeof(ips_record_rle_t);

/*			printf("[RLE]\t%06x <- len:%u\t[%02x]\n",
				BYTE3_TO_UINT32(ips_data[ips_count-1].info->offset),
				BYTE2_TO_UINT16( ((ips_record_rle_t*)ips_data[ips_count-1].data)->rle_size ),
				((ips_record_rle_t*)ips_data[ips_count-1].data)->byte); */
		} else {
			offset_in += BYTE2_TO_UINT16(ips_data[ips_count-1].info->size);

/*			printf("[NORM]\t%06x <- len:%u\t[%02x ... %02x]\n",
				BYTE3_TO_UINT32(ips_data[ips_count-1].info->offset),
				BYTE2_TO_UINT16(ips_data[ips_count-1].info->size  ),
				((uint8_t*)(ips_data[ips_count-1].data))[0],
				((uint8_t*)(ips_data[ips_count-1].data))[ BYTE2_TO_UINT16(ips_data[ips_count-1].info->size) - 1] ); */
		}

		// Aaand onto the next.
	}

	printf("Read in IPS data. Record count: %d\n", ips_count);

	ips_structs[0] = ips_data;

	return ips_count;
}

int split_ips(__READ const char* filename, __READ ips_record_t* records, __READ int record_count) {
	char* name = strdup("00000000.ips");

	for (int i=0; i < record_count; i++) {

		uint32_t offset = BYTE3_TO_UINT32(records[i].info->offset);

		sprintf(name, "%08X.ips", offset);
		FILE* patch = fopen(name, "w");

		fwrite(IPS_MAGIC, 1, IPS_MAGIC_LENGTH, patch); // Write header
		fwrite(records[i].info, 1, sizeof(ips_record_com_t), patch); // Write patch record.

		uint16_t size = BYTE2_TO_UINT16(records[i].info->size);

		if (size == 0) // RLE
			fwrite(records[i].data, 1, sizeof(ips_record_rle_t), patch); // Write RLE struct.
		else // Normal Data
			fwrite(records[i].data, 1, size, patch);

		fwrite((void*)IPS_TAIL, 1, IPS_TAIL_LENGTH, patch); // Write footer

		fclose(patch);
	}

	free(name);
}


int dump_ips_pt(__READ const char* filename, __READ ips_record_t* records, __READ int record_count) {
	FILE* plain = fopen(filename, "w");

	uint32_t       max_size = 0;
	for (int i=0; i < record_count; i++) {
		uint32_t write = BYTE4_TO_UINT32(records[i].info->offset);
		uint16_t size = BYTE2_TO_UINT16(records[i].info->size);
		if (size == 0) {
			size = BYTE2_TO_UINT16( ((ips_record_rle_t*)records[i].data)->rle_size );
		}

		write += size;

		if (write > max_size)
			max_size = write;
	}

	fprintf(plain, "Patch file: format 'PATCH'\n");
	fprintf(plain, "Maximum write offset: %u bytes\n", max_size);
	fprintf(plain, "-----\n");


	for (int i=0; i < record_count; i++) {
		uint32_t offset = BYTE3_TO_UINT32(records[i].info->offset);
		uint16_t size = BYTE2_TO_UINT16(records[i].info->size);

		if (size == 0) { // RLE
			ips_record_rle_t* rle = (ips_record_rle_t*)records[i].data;

			size = BYTE2_TO_UINT16(rle->rle_size);

			fprintf(plain, "%08X: RLE\nValue %02x, write %u times\n", offset, rle->byte, size);
		} else { // Normal
			uint8_t* bytes = (uint8_t*)records[i].data;

			fprintf(plain, "%08X: Normal, length is %u\n", offset, size);

			hexdump_manual(offset, bytes, size, USE_SPACES | BYTE_A | WITH_ASCII | LINE_BREAKS | CENTER_SPLIT | NONPRINT_PERIOD, plain);
		}

		fprintf(plain, "-----\n");
	}

	fclose(plain);

	return 0;
}

int apply_ips(__READ const char* filename, __READ ips_record_t* records, __READ int record_count) {
	// First; a bit of business. IPS patches can write past a file's
	// bounds, so we need to calculate the largest possible write.
	// This involves scanning through the IPS structs.

	uint32_t       max_size = 0;
	for (int i=0; i < record_count; i++) {
		uint32_t write = BYTE3_TO_UINT32(records[i].info->offset);
		uint16_t size = BYTE2_TO_UINT16(records[i].info->size);
		if (size == 0) {
			size = BYTE2_TO_UINT16( ((ips32_record_rle_t*)records[i].data)->rle_size );
		}

		write += size;

		if (write > max_size)
			max_size = write;
	}

	// Simulations shouldn't modify file size.
	printf("End offset of IPS is %u\n", max_size);

	if (simulate) return 0; // None of the below will actually do anything while simulated.

	// Load file in R/W mmap, with expansion.
	map_file_expand(filename, max_size);

	for (int i=0; i < record_count; i++) {
		uint32_t offset = BYTE3_TO_UINT32(records[i].info->offset);
		uint16_t size = BYTE2_TO_UINT16(records[i].info->size);

		if (size == 0) { // RLE
			ips_record_rle_t* rle = (ips_record_rle_t*)records[i].data;

			size = BYTE2_TO_UINT16(rle->rle_size);

			if (!simulate)
				for(int i=0; i < size; i++)
					blib_buffer[offset+i] = rle->byte;
		} else { // Normal
			uint8_t* bytes = (uint8_t*)records[i].data;

			if (!simulate)
				for(int i=0; i < size; i++)
					blib_buffer[offset+i] = bytes[i];
		}
	}

	unmap_file();

	return 0;
}


// On success, returns the number of IPS records read. On failure,
// returns -1.
int load_ips32(__READ char* ips_filename, __WRITE ips32_record_t** ips_structs) {
	// We load the entire thing to memory.

	FILE* f = fopen(ips_filename, "r");
	fseek(f, 0, SEEK_END);
	uint64_t pos = ftell(f);
	rewind(f);

	ips_buffer = (uint8_t*)malloc(pos);

	fread(ips_buffer, 1, pos, f);

	fclose(f);

	printf("Loaded file to memory successfully. Size: %lld\n", pos);

	// Loaded. Begin by checking shit.
	if( strncmp(ips_buffer, IPS32_MAGIC, IPS32_MAGIC_LENGTH) ) {
		// Invalid signature. Not an IPS.
		free(ips_buffer);
		ips_buffer = NULL;
		return -1;
	}

	// Seems legit. Begin record calculation.
	int ips_count = 0;
	uint64_t offset_in = 5;
	ips32_record_t* ips_data = NULL;
	while( offset_in < pos && strncmp((char*)&ips_buffer[offset_in], IPS32_TAIL, IPS32_TAIL_LENGTH) ) {
		// Increment.
		ips_count++;

		// Reallocate.
		ips_data = (ips32_record_t*)realloc(ips_data, sizeof(ips32_record_t) * ips_count);

		ips_data[ips_count-1].info = (ips32_record_com_t*)&ips_buffer[offset_in];

		offset_in += sizeof(ips32_record_com_t);

		ips_data[ips_count-1].data = (void*)&ips_buffer[offset_in];

		if(ips_data[ips_count-1].info->size[0] == 0x00 && ips_data[ips_count-1].info->size[1] == 0x00) { // Zero is zero regardless of byte order, no casting needed
			// RLE. Add the size of an RLE struct.
			offset_in += sizeof(ips32_record_rle_t);

/*			printf("[RLE]\t%u <- len:%u\t[%02x]\n",
				BYTE4_TO_UINT32(ips_data[ips_count-1].info->offset),
				BYTE2_TO_UINT16( ((ips32_record_rle_t*)ips_data[ips_count-1].data)->rle_size ),
				((ips32_record_rle_t*)ips_data[ips_count-1].data)->byte); */
		} else {
			offset_in += BYTE2_TO_UINT16(ips_data[ips_count-1].info->size);

/*			printf("[NORM]\t%u <- len:%u\t[%02x ... %02x]\n",
				BYTE4_TO_UINT32(ips_data[ips_count-1].info->offset),
				BYTE2_TO_UINT16(ips_data[ips_count-1].info->size  ),
				((uint8_t*)(ips_data[ips_count-1].data))[0],
				((uint8_t*)(ips_data[ips_count-1].data))[ BYTE2_TO_UINT16(ips_data[ips_count-1].info->size) - 1] ); */
		}

		// Aaand onto the next.
	}

	printf("Read in IPS data. Record count: %d\n", ips_count);

	ips_structs[0] = ips_data;

	return ips_count;
}

int split_ips32(__READ const char* filename, __READ ips32_record_t* records, __READ int record_count) {
	char* name = strdup("00000000.ips");

	for (int i=0; i < record_count; i++) {

		uint32_t offset = BYTE4_TO_UINT32(records[i].info->offset);

		sprintf(name, "%08X.ips", offset);
		FILE* patch = fopen(name, "w");

		fwrite((void*)IPS32_MAGIC, 1, IPS32_MAGIC_LENGTH, patch); // Write header
		fwrite(& records[i].info, 1, sizeof(ips32_record_com_t), patch); // Write patch record.

		uint16_t size = BYTE2_TO_UINT16(records[i].info->size);

		if (size == 0) // RLE
			fwrite(records[i].data, 1, sizeof(ips32_record_rle_t), patch); // Write RLE struct.
		else // Normal Data
			fwrite(records[i].data, 1, size, patch);

		fwrite((void*)IPS32_TAIL, 1, IPS32_TAIL_LENGTH, patch); // Write footer

		fclose(patch);
	}

	free(name);
}


int dump_ips32_pt(__READ const char* filename, __READ ips32_record_t* records, __READ int record_count) {
	FILE* plain = fopen(filename, "w");

	uint32_t       max_size = 0;
	for (int i=0; i < record_count; i++) {
		uint32_t write = BYTE4_TO_UINT32(records[i].info->offset);
		uint16_t size = BYTE2_TO_UINT16(records[i].info->size);
		if (size == 0) {
			size = BYTE2_TO_UINT16( ((ips32_record_rle_t*)records[i].data)->rle_size );
		}

		write += size;

		if (write > max_size)
			max_size = write;
	}

	fprintf(plain, "# Patch file: format 'IPS32'\n");
	fprintf(plain, "# Maximum write offset: %u bytes\n", max_size);

	for (int i=0; i < record_count; i++) {
		uint32_t offset = BYTE4_TO_UINT32(records[i].info->offset);
		uint16_t size = BYTE2_TO_UINT16(records[i].info->size);

		if (size == 0) { // RLE
			ips32_record_rle_t* rle = (ips32_record_rle_t*)records[i].data;

			size = BYTE2_TO_UINT16(rle->rle_size);

			fprintf(plain, "%08X: RLE\nValue %02x, write %u times\n", offset, rle->byte, size);
		} else { // Normal
			uint8_t* bytes = (uint8_t*)records[i].data;

			fprintf(plain, "%08X: Normal, length is %u\n", offset, size);

			for(int i=0; i < size; i++)
				fprintf(plain, "%02x ", bytes[i]);

			fprintf(plain, "\n");
		}
	}

	fclose(plain);

	return 0;
}

int apply_ips32(__READ const char* filename, __READ ips32_record_t* records, __READ int record_count) {
	// First; a bit of business. IPS patches can write past a file's
	// bounds, so we need to calculate the largest possible write.
	// This involves scanning through the IPS structs.

	uint32_t       max_size = 0;
	for (int i=0; i < record_count; i++) {
		uint32_t write = BYTE4_TO_UINT32(records[i].info->offset);
		uint16_t size = BYTE2_TO_UINT16(records[i].info->size);
		if (size == 0) {
			size = BYTE2_TO_UINT16( ((ips32_record_rle_t*)records[i].data)->rle_size );
		}

		write += size;

		if (write > max_size)
			max_size = write;
	}

	// Simulations shouldn't modify file size.
	printf("End offset of IPS is %u\n", max_size);

	if (simulate) return 0; // None of the below will actually do anything while simulated.

	// Load file in R/W mmap, with expansion.
	map_file_expand(filename, max_size);

	for (int i=0; i < record_count; i++) {
		uint32_t offset = BYTE4_TO_UINT32(records[i].info->offset);
		uint16_t size = BYTE2_TO_UINT16(records[i].info->size);

		if (size == 0) { // RLE
			ips32_record_rle_t* rle = (ips32_record_rle_t*)records[i].data;

			size = BYTE2_TO_UINT16(rle->rle_size);

			if (!simulate)
				for(int i=0; i < size; i++)
					blib_buffer[offset+i] = rle->byte;
		} else { // Normal
			uint8_t* bytes = (uint8_t*)records[i].data;

			if (!simulate)
				for(int i=0; i < size; i++)
					blib_buffer[offset+i] = bytes[i];
		}
	}

	unmap_file();

	return 0;
}

void generate_ips_opt(uint8_t* from, size_t from_len, uint8_t* to, size_t to_len, ips_record_t** ips_dat_out, size_t* ips_record_out) {
	// Pass one - 1byte = 1chunk
	ips_record_t* ips_dat = NULL;
	size_t record_num = 0;

	uint32_t i=0;
	size_t end_same = MIN(from_len, to_len); // We want whatever is smaller.

	// We first build an incredibly unoptimized patch.
	for(int i=0; i < end_same; i++) {
		if (from[i] != to[i]) {
			// Create a patch record.
			++record_num;
			ips_dat = realloc(ips_dat, record_num*sizeof(ips_record_t));
			ips_dat[record_num-1].info = calloc(1, sizeof(ips_record_com_t));

			ips_dat[record_num-1].info->offset[0] = (i >> 16) & 0xFF;
			ips_dat[record_num-1].info->offset[1] = (i >> 8) & 0xFF;
			ips_dat[record_num-1].info->offset[2] = i & 0xFF;

			ips_dat[record_num-1].data = &to[i];

			ips_dat[record_num-1].info->size[0] = 0;
			ips_dat[record_num-1].info->size[1] = 1;
		}
	}

	printf("Number of changed bytes: %lu\n", record_num);

	ips_record_t* current = ips_dat;
	ips_dat = NULL;

	size_t rled_num = 0;

	// Next, we go through and convert potential sequences of RLEs.
	// RLE is a increase in size unless conditions are met:

	// If isolated (e.g. surrounded by same)
	//   Must be >3 bytes
	// If Next to changes:
	//   RLE must be >8 bytes

	while(i < record_num) {
		// Combine adjacents if relevant.
		int streak = 0;
		for( ; i+streak < record_num-1 && streak < 0xffff; streak++) {
			uint32_t at   = BYTE3_TO_UINT32(current[i+streak].info->offset);
			uint32_t next = BYTE3_TO_UINT32(current[i+streak+1].info->offset);
			uint8_t  at_byte   = ((uint8_t*)current[i+streak].data)[0];
			uint8_t  next_byte = ((uint8_t*)current[i+streak+1].data)[0];
			if (at+1 != next || at_byte != next_byte)
				break;
		}
		streak++;

		rled_num++;

		ips_dat = realloc(ips_dat, rled_num*sizeof(ips_record_t));
		ips_dat[rled_num-1].info = calloc(1, sizeof(ips_record_com_t));

		ips_dat[rled_num-1].info->offset[0] = current[i].info->offset[0];
		ips_dat[rled_num-1].info->offset[1] = current[i].info->offset[1];
		ips_dat[rled_num-1].info->offset[2] = current[i].info->offset[2];

		if (streak < 4) {
			// No RLE. Copy and move on.
			ips_dat[rled_num-1].info->size[0] = 0;
			ips_dat[rled_num-1].info->size[1] = 1;
			ips_dat[rled_num-1].data = current[i].data;

			i += 1;
		} else {
			// Potentially RLE.

			int require_extra = 0;
			// Is the left side an adjacent patch?
			if (i > 0) {
				// If i is zero, we're at the beginning so this isn't needed
				uint32_t prev = BYTE3_TO_UINT32(current[i-1].info->offset);
				uint32_t cur  = BYTE3_TO_UINT32(current[i].info->offset);

				if (prev+1 == cur)
					require_extra += 1; // We're next to another chunk.
			}

			// Is the right side an adjacent patch?
			if (i+streak+1 < record_num) {
				uint32_t next = BYTE3_TO_UINT32(current[i+streak+1].info->offset);
				uint32_t cur  = BYTE3_TO_UINT32(current[i+streak].info->offset);

				if (cur+1 == next)
					require_extra += 1; // Next to another chunk.
			}

			int must_be_n = 0;
			switch (require_extra) {
				case 0:
					must_be_n = 4;
					break;
				case 1:
					must_be_n = 9;
					break;
				case 2:
					must_be_n = 14;
					break;
			}

			if (streak >= must_be_n) {
				// Use RLE encoding here.
				ips_dat[rled_num-1].info->size[0] = 0; // Marks RLE.
				ips_dat[rled_num-1].info->size[1] = 0; // Marks RLE.

				ips_dat[rled_num-1].data = calloc(1, sizeof(ips_record_rle_t));
				((ips_record_rle_t*)(ips_dat[rled_num-1].data))->rle_size[0] = (streak >> 8) & 0xFF;
				((ips_record_rle_t*)(ips_dat[rled_num-1].data))->rle_size[1] = streak & 0xFF;
				((ips_record_rle_t*)(ips_dat[rled_num-1].data))->byte = ((uint8_t*)current[i].data)[0];

				i += streak; // Skip things in the RLE.
			} else {
				// Standard copy.
				ips_dat[rled_num-1].info->size[0] = 0;
				ips_dat[rled_num-1].info->size[1] = 1;
				ips_dat[rled_num-1].data = current[i].data;

				i += 1;
			}
		}
	}

	printf("Number of records after RLE pass: %lu\n", rled_num);

	// Free everything from current.
	for(int i=0; i < record_num; i++) {
		free(current[i].info);
	}
	free(current);

	current = ips_dat;

	ips_dat = NULL;

	size_t final_num = 0;

	// RLE optimizations have been applied. Loop thru now and combine
	// all adjacent 1byte records
	i = 0;
	while(i < rled_num) {
		if (BYTE2_TO_UINT16(current[i].info->size) == 0) {
			// RLE chunks get copied as-is.
			final_num++;

			ips_dat = realloc(ips_dat, final_num*sizeof(ips_record_t));
			ips_dat[final_num-1].info = calloc(1, sizeof(ips_record_com_t));

			ips_dat[final_num-1].info->offset[0] = current[i].info->offset[0];
			ips_dat[final_num-1].info->offset[1] = current[i].info->offset[1];
			ips_dat[final_num-1].info->offset[2] = current[i].info->offset[2];

			ips_dat[final_num-1].info->size[0] = current[i].info->size[0];
			ips_dat[final_num-1].info->size[1] = current[i].info->size[1];

			ips_dat[final_num-1].data = calloc(1, sizeof(ips_record_rle_t));

			((ips_record_rle_t*)(ips_dat[final_num-1].data))->rle_size[0] = ((ips_record_rle_t*)(current[i].data))->rle_size[0];
			((ips_record_rle_t*)(ips_dat[final_num-1].data))->rle_size[1] = ((ips_record_rle_t*)(current[i].data))->rle_size[1];
			((ips_record_rle_t*)(ips_dat[final_num-1].data))->byte    = ((ips_record_rle_t*)(current[i].data))->byte;

			i++;
		} else {
			// Combine adjacents if relevant.
			int streak = 0;
			for( ; i+streak < rled_num-1 && streak < 0xffff; streak++) {
				uint32_t at   = BYTE3_TO_UINT32(current[i+streak].info->offset);
				uint32_t next = BYTE3_TO_UINT32(current[i+streak+1].info->offset);
				uint32_t next_rle = BYTE3_TO_UINT32(current[i+streak+1].info->size);
				if (at+1 != next || next_rle == 0)
					break;
			}
			streak++;

			// Normals actually still point into the original memory, so
			// data actually stays and we just change the size.

			final_num++;

			ips_dat = realloc(ips_dat, final_num*sizeof(ips_record_t));
			ips_dat[final_num-1].info = calloc(1, sizeof(ips_record_com_t));

			ips_dat[final_num-1].info->offset[0] = current[i].info->offset[0];
			ips_dat[final_num-1].info->offset[1] = current[i].info->offset[1];
			ips_dat[final_num-1].info->offset[2] = current[i].info->offset[2];

			ips_dat[final_num-1].info->size[0] = (streak >> 8) & 0xFF;
			ips_dat[final_num-1].info->size[1] = streak & 0xFF;

			ips_dat[final_num-1].data = current[i].data;

			i += streak;
		}
	}

	printf("Number of records after combine pass: %lu\n", final_num);

	// Free everything from current.
	for(int i=0; i < rled_num; i++) {
		free(current[i].info);
	}
	free(current);

	ips_record_out[0] = final_num;
	ips_dat_out[0] = ips_dat;
}

void generate_ips(uint8_t* from, size_t from_len, uint8_t* to, size_t to_len, ips_record_t** ips_dat_out, size_t* ips_record_out) {
	ips_record_t* ips_dat = NULL;
	size_t record_num = 0;

	uint32_t i=0;
	size_t end_same = MIN(from_len, to_len); // We want whatever is smaller.

	while(1) {
		++record_num;

		// Allocate a new struct.
		ips_dat = realloc(ips_dat, record_num*sizeof(ips_record_t));
		ips_dat[record_num-1].info = calloc(1, sizeof(ips_record_com_t));

		for(; i < end_same; i++) {
			// Seek until the first *different* bit.
			if (from[i] != to[i]) break;
		}

		// End of file?
		if (i >= end_same - 1) {
			free(ips_dat[record_num-1].info);
			--record_num;
			ips_dat = realloc(ips_dat, record_num*sizeof(ips_record_t));
			break;
		}

		ips_dat[record_num-1].info->offset[0] = (i >> 16) & 0xFF;
		ips_dat[record_num-1].info->offset[1] = (i >> 8) & 0xFF;
		ips_dat[record_num-1].info->offset[2] = i & 0xFF;

		// Different bit.

		ips_dat[record_num-1].data = &to[i];
		uint16_t write_len = 0;

		for(; i < end_same; i++) {
			if (from[i] == to[i]) break; // Same bit.
			++write_len;
		}

		ips_dat[record_num-1].info->size[0] = (write_len >> 8) & 0xFF;
		ips_dat[record_num-1].info->size[1] = write_len & 0xFF;

		if (i >= end_same - 1) break;
	}

	ips_record_out[0] = record_num;
	ips_dat_out[0] = ips_dat;
}

void generate_ips32(uint8_t* from, size_t from_len, uint8_t* to, size_t to_len, ips32_record_t** ips_dat_out, size_t* ips_record_out) {
	ips32_record_t* ips_dat = NULL;
	size_t record_num = 0;

	uint32_t i=0;
	size_t end_same = MIN(from_len, to_len); // We want whatever is smaller.

	while(1) {
		++record_num;

		// Allocate a new struct.
		ips_dat = realloc(ips_dat, record_num*sizeof(ips32_record_t));
		ips_dat[record_num-1].info = calloc(1, sizeof(ips32_record_com_t));

		for(; i < end_same; i++) {
			// Seek until the first *different* bit.
			if (from[i] != to[i]) break;
		}

		// End of file?
		if (i >= end_same - 1) {
			free(ips_dat[record_num-1].info);
			--record_num;
			ips_dat = realloc(ips_dat, record_num*sizeof(ips32_record_t));
			break;
		}
		ips_dat[record_num-1].info->offset[0] = (i >> 24) & 0xFF;
		ips_dat[record_num-1].info->offset[1] = (i >> 16) & 0xFF;
		ips_dat[record_num-1].info->offset[2] = (i >> 8) & 0xFF;
		ips_dat[record_num-1].info->offset[3] = i & 0xFF;

		// Different bit.

		ips_dat[record_num-1].data = &to[i];
		uint16_t write_len = 0;

		for(; i < end_same; i++) {
			if (from[i] == to[i]) break; // Same bit.
			++write_len;
		}

		ips_dat[record_num-1].info->size[0] = (write_len >> 8) & 0xFF;
		ips_dat[record_num-1].info->size[1] = write_len & 0xFF;

		if (i >= end_same - 1) break;
	}

	ips_record_out[0] = record_num;
	ips_dat_out[0] = ips_dat;
}

int identify_patch(__READ const char* filename) {
	char test[8];
	FILE* f = fopen(filename, "r");
	fseek(f, 0, SEEK_END);
	if (ftell(f) < 8) {
		// Wrong. No patch is smaller than this. Die.
		return TYPE_INVALID;
	}
	rewind(f);
	fread(test, 1, 8, f);

	fclose(f);

	if ( !strncmp(test, IPS_MAGIC, IPS_MAGIC_LENGTH) )
		return TYPE_IPS;
	if ( !strncmp(test, IPS32_MAGIC, IPS32_MAGIC_LENGTH) )
		return TYPE_IPS32;

	return TYPE_INVALID;
}

void help(char* name) {
	printf("%s bips\n", PACKAGE_STRING);
	printf("(C) 2015 Jon Feldman (@chaoskagami) <%s>\n", PACKAGE_BUGREPORT);
	printf("Usage:\n");
	printf("Apply a patch:\n");
	printf("   %s a [args] patch file [output_file]\n", name);
	printf("Generate a patch:\n");
	printf("   %s c [args] file_a file_b output_file\n", name);
	printf("Options:\n");
	printf("   -s        Simulate; Only print what would be done, don't actually make any changes.\n");
	printf("   -x        Split each chunk out to separate IPS patches\n");
	printf("   -d        Dump a patch to a format that's human readable.\n");
	printf("   -r        Create a 'raw' patch, with no header nor tail.\n");
	printf("   -f        Force generating patches which would be larger than input files\n");
	printf("Report bugs to <%s>\n", PACKAGE_URL);
	printf("This software is licensed under the MIT license.\n");

}

int main(int argc, char** argv) {
	ips_record_t*   ips   = NULL;
	ips32_record_t* ips32 = NULL;
	int record_count = 0;
	int opt;
	int force = 0;
	int raw = 0;

	while ( (opt = getopt(argc, argv, "hdxsrf")) != -1) {
		switch(opt) {
			case 'h':
				help(argv[0]);
				return 1;
			case 'd':
				plaintext = 1;
				break;
			case 'x':
				splitmini = 1;
				break;
			case 's':
				simulate = 1;
				break;
			case 'r':
				raw = 1;
				break;
			case 'f':
				force = 1;
				break;
			case '?':
				fprintf(stderr, "error: unknown option. Run with -h for more info\n");
				return 1;
			default:
				fprintf(stderr, "error: unknown option. Run with -h for more info\n");
				return 1;
		}
	}

	if (argc - optind < 3) {
		fprintf(stderr, "error: requires more arguments. Run with -h for more info\n");
		return 1;
	}

	int operation = 0;
	switch(argv[optind][0]) {
		case 'a':
			operation = 0;
			break;
		case 'c':
			operation = 1;
			break;
		default:
			break;
	}

	if (operation == 0) {
		char* patch  = argv[optind+1];
		int type = identify_patch(patch);
		char* input  = argv[optind+2];

		if (splitmini == 1) {
			switch(type) {
				case TYPE_IPS:
					printf("Patch format: IPS (24-bit offsets)\n");
					record_count = load_ips(patch, &ips);
					split_ips(input, ips, record_count);
					break;
				case TYPE_IPS32:
					printf("Patch format: IPS32 (IPS derivative w/ 32-bit offsets)\n");
					record_count = load_ips32(argv[optind+1], &ips32);
					split_ips32(input, ips32, record_count);
					break;
				default:
					printf("Patch format not understood or invalid.\n");
					break;
			}
		} else if (plaintext == 1) {
			switch(type) {
				case TYPE_IPS:
					printf("Patch format: IPS (24-bit offsets)\n");
					record_count = load_ips(patch, &ips);
					dump_ips_pt(input, ips, record_count);
					break;
				case TYPE_IPS32:
					printf("Patch format: IPS32 (IPS derivative w/ 32-bit offsets)\n");
					record_count = load_ips32(patch, &ips32);
					dump_ips32_pt(input, ips32, record_count);
					break;
				default:
					printf("Patch format not understood or invalid.\n");
					break;
			}
		} else {
			char* out_file = input;
			if (argc - optind == 4) {
				// Output file is specified. Copy file.
				int ret = copy_file(argv[optind+3], out_file);

				if (ret) {
					printf("Error copying file '%s' to '%s'\n", out_file, argv[optind+3]);
					return -1; // Error.
				}

				printf("Copied file '%s' to '%s'\n", out_file, argv[optind+3]);

				out_file = argv[optind+3];
			}

			if (simulate)
				printf("Patching is simulated; e.g. won't be written to disk.\n");

			switch(type) {
				case TYPE_IPS:
					printf("Patch format: IPS (24-bit offsets)\n");
					record_count = load_ips(patch, &ips);
					apply_ips(out_file, ips, record_count);
					break;
				case TYPE_IPS32:
					printf("Patch format: IPS32 (IPS derivative w/ 32-bit offsets)\n");
					record_count = load_ips32(patch, &ips32);
					apply_ips32(out_file, ips32, record_count);
					break;
				default:
					printf("Patch format not understood or invalid.\n");
					break;
			}
		}

		free(ips);
		free(ips32);
		free(ips_buffer);
	} else if (operation == 1) {
		FILE* a = fopen(argv[optind+1], "rb");
		FILE* b = fopen(argv[optind+2], "rb");
		fseek(a, 0, SEEK_END);
		fseek(b, 0, SEEK_END);
		size_t a_len = ftell(a);
		size_t b_len = ftell(b);
		rewind(a);
		rewind(b);
		if (b_len > 0xFFFFFFFF) {
			// ...Too large.
			fclose(a);
			fclose(b);
			fprintf(stderr, "Files are too large for IPS format.");
			return 1;
		} else if(b_len > 0xFFFFFF) {
			uint8_t* a_d = malloc(a_len);
			fread(a_d, 1, a_len, a);
			fclose(a);
			uint8_t* b_d = malloc(b_len);
			fread(b_d, 1, b_len, b);
			fclose(b);

			// IPS32. Can't fit in IPS.
			size_t records = 0;
			generate_ips32(a_d, a_len, b_d, b_len, &ips32, &records);

			FILE* out = fopen(argv[optind+3], "w");
			if (raw == 0) fwrite(IPS32_MAGIC, 1, IPS32_MAGIC_LENGTH, out);

			for(size_t i=0; i < records; i++) {
				fwrite(&(ips32[i].info), 1, sizeof(ips32_record_com_t), out);
				if (BYTE2_TO_UINT16(ips32[i].info->size) == 0) { // RLE
					fwrite(ips32[i].data, 1, sizeof(ips32_record_rle_t), out);
				} else {
					fwrite(ips32[i].data, 1, BYTE2_TO_UINT16(ips32[i].info->size), out);
				}
			}

			if (raw == 0) fwrite(IPS32_TAIL, 1, IPS32_TAIL_LENGTH, out);

			fclose(out);

			return 0;
		} else {
			uint8_t* a_d = malloc(a_len);
			fread(a_d, 1, a_len, a);
			fclose(a);
			uint8_t* b_d = malloc(b_len);
			fread(b_d, 1, b_len, b);
			fclose(b);

			// Plain ol' IPS.
			size_t records = 0;
			generate_ips_opt(a_d, a_len, b_d, b_len, &ips, &records);

			printf("Generated patch consists of %ld records\n", records);
			size_t size = 0;
			for (int i=0; i < records; i++) {
				size += sizeof(ips_record_com_t);
				int t = BYTE2_TO_UINT16(ips[i].info->size);
				if (!t)
					size += sizeof(ips_record_rle_t);
				size += t;
			}
			size += IPS_MAGIC_LENGTH + IPS_TAIL_LENGTH;
			printf("Generated patch output size will be: %ld bytes\n", size);

			if (size > b_len) {
				if (force) {
					printf("WARNING - output patch is larger than input (-f was specified)\n");
				} else {
					printf("ERROR - output patch is larger than input\n");
					// Clean up.
					exit(1);
				}
			}

			FILE* out = fopen(argv[optind+3], "w");
			if (raw == 0) fwrite(IPS_MAGIC, 1, IPS_MAGIC_LENGTH, out);

			for(size_t i=0; i < records; i++) {
				fwrite(ips[i].info, 1, sizeof(ips_record_com_t), out);
				if (BYTE2_TO_UINT16(ips[i].info->size) == 0) { // RLE
					fwrite(ips[i].data, 1, sizeof(ips_record_rle_t), out);
				} else {
					fwrite(ips[i].data, 1, BYTE2_TO_UINT16(ips[i].info->size), out);
				}
			}

			if (raw == 0) fwrite(IPS_TAIL, 1, IPS_TAIL_LENGTH, out);

			fclose(out);

			printf("Done\n", records);

			return 0;
		}
	}
}
