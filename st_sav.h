#ifndef ST_SAV_H
#define ST_SAV_H

#include <stdio.h>

typedef enum {
	BLOCK_1,  // TODO name blocks
	BLOCK_2,
	BLOCK_4,
	BLOCK_5,
	BLOCK_3,
	BLOCK_6
} STBlockType;

#define BLOCK_1_SIZE  (0x50)
#define BLOCK_2_SIZE  (0x45C)
#define BLOCK_3_SIZE  (0x358)
#define BLOCK_4_SIZE  (0x874)
#define BLOCK_5_SIZE  (0x591C)
#define BLOCK_6_SIZE  (0x8)

typedef enum {
	ST_ERR_NONE,
	ST_ERR_CRC,
	ST_ERR_MD5
} STErrCode;


// Read a block from an open save file. Data is allocated and the pointer written to *out_ptr. This must be freed later.
// Returns an error code based on block integrity. If not ST_ERR_NONE, data pointer will be null.
STErrCode ST_GetSavBlock(void** out_ptr, STBlockType block_type, FILE* in_sav);


// Write a block to an open save file. Does not free.
void ST_PutSavBlock(FILE* out_sav, STBlockType block_type, const void* in_data);


// Pad a newly create file to 64kB with FF bytes.
void ST_PadSav(FILE* out_sav);


#endif
