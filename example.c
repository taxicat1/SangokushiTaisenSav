#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "st_sav.h"


int main(int argc, char* argv[]) {
	if (argc != 3) {
		return 1;
	}
	
	FILE* in = fopen(argv[1], "rb");
	FILE* out = fopen(argv[2], "wb");
	if (in == NULL || out == NULL) {
		return 1;
	}
	
	void* block1;
	void* block2;
	void* block3;
	void* block4;
	void* block5;
	void* block6;
	
	ST_GetSavBlock(&block1, BLOCK_1, in);
	ST_GetSavBlock(&block2, BLOCK_2, in);
	ST_GetSavBlock(&block3, BLOCK_3, in);
	ST_GetSavBlock(&block4, BLOCK_4, in);
	ST_GetSavBlock(&block5, BLOCK_5, in);
	ST_GetSavBlock(&block6, BLOCK_6, in);
	fclose(in);
	
	// Do something with block data
	
	// Dump to bins
	FILE* out1 = fopen("block1.bin", "wb");
	fwrite(block1, 1, BLOCK_1_SIZE, out1);
	fclose(out1);
	
	FILE* out2 = fopen("block2.bin", "wb");
	fwrite(block1, 1, BLOCK_2_SIZE, out2);
	fclose(out2);
	
	FILE* out3 = fopen("block3.bin", "wb");
	fwrite(block1, 1, BLOCK_3_SIZE, out3);
	fclose(out3);
	
	FILE* out4 = fopen("block4.bin", "wb");
	fwrite(block1, 1, BLOCK_4_SIZE, out4);
	fclose(out4);
	
	FILE* out5 = fopen("block5.bin", "wb");
	fwrite(block1, 1, BLOCK_5_SIZE, out5);
	fclose(out5);
	
	FILE* out6 = fopen("block6.bin", "wb");
	fwrite(block1, 1, BLOCK_6_SIZE, out6);
	fclose(out6);
	
	// Copy to a new save file (re-encrypting)
	ST_PutSavBlock(out, BLOCK_1, block1);
	ST_PutSavBlock(out, BLOCK_2, block2);
	ST_PutSavBlock(out, BLOCK_3, block3);
	ST_PutSavBlock(out, BLOCK_4, block4);
	ST_PutSavBlock(out, BLOCK_5, block5);
	ST_PutSavBlock(out, BLOCK_6, block6);
	ST_PadSav(out);
	fclose(out);
	
	free(block1);
	free(block2);
	free(block3);
	free(block4);
	free(block5);
	free(block6);
	
	return 0;
}