#ifndef ST_SAV_H
#define ST_SAV_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

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
	ST_ERR_NONE = 0,
	ST_ERR_CRC,
	ST_ERR_MD5
} STErrCode;


// Read a block from an open save file. Data is allocated and the pointer written to *out_ptr. This must be freed later.
// Returns an error code based on block integrity. If not ST_ERR_NONE, data pointer will be null.
STErrCode ST_GetSavBlockData(void** out_ptr, STBlockType block_type, FILE* in_sav);

static inline STErrCode ST_GetSavBlock1Data(void** out_ptr, FILE* in_sav) {
	return ST_GetSavBlockData(out_ptr, BLOCK_1, in_sav);
}

static inline STErrCode ST_GetSavBlock2Data(void** out_ptr, FILE* in_sav) {
	return ST_GetSavBlockData(out_ptr, BLOCK_2, in_sav);
}

static inline STErrCode ST_GetSavBlock3Data(void** out_ptr, FILE* in_sav) {
	return ST_GetSavBlockData(out_ptr, BLOCK_3, in_sav);
}

static inline STErrCode ST_GetSavBlock4Data(void** out_ptr, FILE* in_sav) {
	return ST_GetSavBlockData(out_ptr, BLOCK_4, in_sav);
}

static inline STErrCode ST_GetSavBlock5Data(void** out_ptr, FILE* in_sav) {
	return ST_GetSavBlockData(out_ptr, BLOCK_5, in_sav);
}

static inline STErrCode ST_GetSavBlock6Data(void** out_ptr, FILE* in_sav) {
	return ST_GetSavBlockData(out_ptr, BLOCK_6, in_sav);
}


// Write a block to an open save file. Does not free.
void ST_PutSavBlockData(FILE* out_sav, STBlockType block_type, const void* in_data);

static inline void ST_PutSavBlock1Data(FILE* out_sav, const void* in_data) {
	ST_PutSavBlockData(out_sav, BLOCK_1, in_data);
}

static inline void ST_PutSavBlock2Data(FILE* out_sav, const void* in_data) {
	ST_PutSavBlockData(out_sav, BLOCK_2, in_data);
}

static inline void ST_PutSavBlock3Data(FILE* out_sav, const void* in_data) {
	ST_PutSavBlockData(out_sav, BLOCK_3, in_data);
}

static inline void ST_PutSavBlock4Data(FILE* out_sav, const void* in_data) {
	ST_PutSavBlockData(out_sav, BLOCK_4, in_data);
}

static inline void ST_PutSavBlock5Data(FILE* out_sav, const void* in_data) {
	ST_PutSavBlockData(out_sav, BLOCK_5, in_data);
}

static inline void ST_PutSavBlock6Data(FILE* out_sav, const void* in_data) {
	ST_PutSavBlockData(out_sav, BLOCK_6, in_data);
}



// Pad a newly create file to 64kB with FF bytes.
void ST_PadSav(FILE* out_sav);


typedef struct {
	void*      block1Data;
	STErrCode  block1ErrCode;
	void*      block2Data;
	STErrCode  block2ErrCode;
	void*      block3Data;
	STErrCode  block3ErrCode;
	void*      block4Data;
	STErrCode  block4ErrCode;
	void*      block5Data;
	STErrCode  block5ErrCode;
	void*      block6Data;
	STErrCode  block6ErrCode;
} ST_Sav;

static inline bool ST_SavDataImport(ST_Sav* out_data, FILE* in_sav) {
	out_data->block1ErrCode = ST_GetSavBlock1Data(&out_data->block1Data, in_sav);
	out_data->block2ErrCode = ST_GetSavBlock2Data(&out_data->block2Data, in_sav);
	out_data->block3ErrCode = ST_GetSavBlock3Data(&out_data->block3Data, in_sav);
	out_data->block4ErrCode = ST_GetSavBlock4Data(&out_data->block4Data, in_sav);
	out_data->block5ErrCode = ST_GetSavBlock5Data(&out_data->block5Data, in_sav);
	out_data->block6ErrCode = ST_GetSavBlock6Data(&out_data->block6Data, in_sav);
	
	return (out_data->block1ErrCode +
	        out_data->block2ErrCode +
	        out_data->block3ErrCode +
	        out_data->block4ErrCode +
	        out_data->block5ErrCode +
	        out_data->block6ErrCode) == 0;
}

static inline void ST_SavDataExport(const ST_Sav* in_data, FILE* out_sav) {
	ST_PutSavBlock1Data(out_sav, in_data->block1Data);
	ST_PutSavBlock2Data(out_sav, in_data->block2Data);
	ST_PutSavBlock3Data(out_sav, in_data->block3Data);
	ST_PutSavBlock4Data(out_sav, in_data->block4Data);
	ST_PutSavBlock5Data(out_sav, in_data->block5Data);
	ST_PutSavBlock6Data(out_sav, in_data->block6Data);
	ST_PadSav(out_sav);
}

static inline void ST_SavDataFree(ST_Sav* in_data) {
	free(in_data->block1Data);
	free(in_data->block2Data);
	free(in_data->block3Data);
	free(in_data->block4Data);
	free(in_data->block5Data);
	free(in_data->block6Data);
}


#endif
