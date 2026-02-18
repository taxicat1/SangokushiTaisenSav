#include "st_sav.h"
#include "sha1.h"
#include "hmac.h"
#include "md5.h"
#include "xorshift.h"
#include "crc.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	uint8_t   MD5[MD5_DIGEST_SIZE];
	uint32_t  CRC;
} BlockFooter;

typedef struct {
	STBlockType  type;
	size_t       offset;
	size_t       dataLength;
	size_t       paddedLength;
	bool         encrypted;
} BlockInfo;

static const BlockInfo* getBlockInfo(STBlockType target_block);
static void decryptBlockData(void* out_data, const void* in_block, const BlockInfo* info);
static void encryptBlockData(void* out_block, const void* in_data, const BlockInfo* info);


STErrCode ST_GetSavBlock(void** out_ptr, STBlockType block_type, FILE* in_sav) {
	int ret_code = ST_ERR_NONE;
	
	const BlockInfo* info = getBlockInfo(block_type);
	
	void* block = malloc(info->paddedLength);
	void* data = malloc(info->dataLength);
	
	// Read from file
	fseek(in_sav, info->offset, SEEK_SET);
	fread(block, 1, info->paddedLength, in_sav);
	
	BlockFooter* footer = (BlockFooter*)((intptr_t)block + info->dataLength);
	
	// Check block CRC
	uint32_t block_crc = footer->CRC;
	footer->CRC = 0;
	if (CRC32(block, info->paddedLength) != block_crc) {
		ret_code = ST_ERR_CRC;
		goto EXIT;
	}
	
	// Copy out data, decrypting if needed
	if (info->encrypted) {
		decryptBlockData(data, block, info);
	} else {
		memcpy(data, block, info->dataLength);
	}
	
	// Check data MD5
	uint8_t computed_md5[MD5_DIGEST_SIZE];
	MD5_Calc(&computed_md5[0], data, info->dataLength);
	if (memcmp(&computed_md5[0], &footer->MD5[0], MD5_DIGEST_SIZE) != 0) {
		ret_code = ST_ERR_MD5;
		goto EXIT;
	}
	
EXIT:
	free(block);
	if (ret_code != ST_ERR_NONE) {
		free(data);
		data = NULL; 
	}
	
	*out_ptr = data;
	return ret_code;
}


void ST_PutSavBlock(FILE* out_sav, STBlockType block_type, const void* in_data) {
	const BlockInfo* info = getBlockInfo(block_type);
	
	void* block = calloc(info->paddedLength, 1);
	BlockFooter* footer = (BlockFooter*)((intptr_t)block + info->dataLength);
	
	// Put data MD5
	MD5_Calc(&footer->MD5[0], in_data, info->dataLength);
	
	// Copy in data, encrypting if needed
	if (info->encrypted) {
		encryptBlockData(block, in_data, info);
	} else {
		memcpy(block, in_data, info->dataLength);
	}
	
	// Put block CRC
	footer->CRC = CRC32(block, info->paddedLength);
	
	// Write to file
	fseek(out_sav, info->offset, SEEK_SET);
	fwrite(block, 1, info->paddedLength, out_sav);
	
	free(block);
}


void ST_PadSav(FILE* out_sav) {
	const BlockInfo* info = getBlockInfo(BLOCK_6);
	size_t offset = info->offset + info->paddedLength;
	fseek(out_sav, offset, SEEK_SET);
	while (offset != 0x10000) {
		uint8_t fill_byte = 0xFF;
		fwrite(&fill_byte, 1, 1, out_sav);
		offset++;
	}
}


#define PADDED_SIZE(size)  ((size + sizeof(BlockFooter) + 0x7F) & ~0x7F)
static const BlockInfo* getBlockInfo(STBlockType target_block) {
	static const BlockInfo blockRecordList[] = {
		{ BLOCK_1,  0x0,    BLOCK_1_SIZE,  PADDED_SIZE(BLOCK_1_SIZE),  false },
		{ BLOCK_2,  0x80,   BLOCK_2_SIZE,  PADDED_SIZE(BLOCK_2_SIZE),  true  },
		{ BLOCK_4,  0x500,  BLOCK_3_SIZE,  PADDED_SIZE(BLOCK_3_SIZE),  true  },
		{ BLOCK_5,  0x880,  BLOCK_4_SIZE,  PADDED_SIZE(BLOCK_4_SIZE),  true  },
		{ BLOCK_3,  0x1180, BLOCK_5_SIZE,  PADDED_SIZE(BLOCK_5_SIZE),  true  },
		{ BLOCK_6,  0x6B00, BLOCK_6_SIZE,  PADDED_SIZE(BLOCK_6_SIZE),  true  }
	};
	
	const BlockInfo* info = &blockRecordList[0];
	while (info->type != target_block) {
		info++;
	}
	
	return info;
}


static void decryptBlockData(void* out_data, const void* in_block, const BlockInfo* info) {
	const BlockFooter* footer = (const BlockFooter*)((intptr_t)in_block + info->dataLength);
	
	uint32_t seed = (info->dataLength << 16) | ((info->dataLength + info->offset) * info->dataLength);
	
	XorShift_Ctx xorshift;
	XorShift_Seed(&xorshift, seed);
	
	uint8_t hmac_key[SHA1_DIGEST_SIZE];
	for (int i = 0; i < SHA1_DIGEST_SIZE; i++) {
		hmac_key[i] = info->dataLength ^ XorShift_Rand(&xorshift);
	}
	
	uint8_t hmac_digest[SHA1_DIGEST_SIZE];
	HMAC_SHA1_Calc(&hmac_digest[0], &footer->MD5[0], MD5_DIGEST_SIZE, &hmac_key[0], SHA1_DIGEST_SIZE);
	
	for (unsigned int i = 0; i < info->dataLength; i++) {
		uint8_t data_byte = ((uint8_t*)in_block)[i];
		
		data_byte ^= hmac_digest[i % 20];
		data_byte -= hmac_digest[19 - (i % 20)];
		
		((uint8_t*)out_data)[i] = data_byte;
		
		hmac_digest[i % 20] += XorShift_Rand(&xorshift);
	}
}


static void encryptBlockData(void* out_block, const void* in_data, const BlockInfo* info) {
	const BlockFooter* footer = (const BlockFooter*)((intptr_t)out_block + info->dataLength);
	
	uint32_t seed = (info->dataLength << 16) | ((info->dataLength + info->offset) * info->dataLength);
	
	XorShift_Ctx xorshift;
	XorShift_Seed(&xorshift, seed);
	
	uint8_t hmac_key[SHA1_DIGEST_SIZE];
	for (int i = 0; i < SHA1_DIGEST_SIZE; i++) {
		hmac_key[i] = info->dataLength ^ XorShift_Rand(&xorshift);
	}
	
	uint8_t hmac_digest[SHA1_DIGEST_SIZE];
	HMAC_SHA1_Calc(&hmac_digest[0], &footer->MD5[0], MD5_DIGEST_SIZE, &hmac_key[0], SHA1_DIGEST_SIZE);
	
	for (unsigned int i = 0; i < info->dataLength; i++) {
		uint8_t data_byte = ((uint8_t*)in_data)[i];
		
		data_byte += hmac_digest[19 - (i % 20)];
		data_byte ^= hmac_digest[i % 20];
		
		((uint8_t*)out_block)[i] = data_byte;
		
		hmac_digest[i % 20] += XorShift_Rand(&xorshift);
	}
}
