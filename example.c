#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "st_sav.h"


int main(int argc, char* argv[]) {
	if (argc != 3) {
		return 1;
	}
	
	FILE* in_file = fopen(argv[1], "rb");
	FILE* out_file = fopen(argv[2], "wb");
	if (in_file == NULL || out_file == NULL) {
		return 1;
	}
	
	ST_Sav sav_data;
	ST_SavDataImport(&sav_data, in_file);
	fclose(in_file);
	
	// Do something with block data
	
	// Dump to bins
	FILE* out1 = fopen("block1.bin", "wb");
	fwrite(sav_data.block1Data, 1, BLOCK_1_SIZE, out1);
	fclose(out1);
	
	FILE* out2 = fopen("block2.bin", "wb");
	fwrite(sav_data.block2Data, 1, BLOCK_2_SIZE, out2);
	fclose(out2);
	
	FILE* out3 = fopen("block3.bin", "wb");
	fwrite(sav_data.block3Data, 1, BLOCK_3_SIZE, out3);
	fclose(out3);
	
	FILE* out4 = fopen("block4.bin", "wb");
	fwrite(sav_data.block4Data, 1, BLOCK_4_SIZE, out4);
	fclose(out4);
	
	FILE* out5 = fopen("block5.bin", "wb");
	fwrite(sav_data.block5Data, 1, BLOCK_5_SIZE, out5);
	fclose(out5);
	
	FILE* out6 = fopen("block6.bin", "wb");
	fwrite(sav_data.block6Data, 1, BLOCK_6_SIZE, out6);
	fclose(out6);
	
	// Copy to a new save file (re-encrypting)
	ST_SavDataExport(&sav_data, out_file);
	fclose(out_file);
	
	ST_SavDataFree(&sav_data);
	
	return 0;
}