#ifndef ST_SAV_H
#define ST_SAV_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

// TODO name blocks
typedef enum {
	BLOCK_1,  // Header
	BLOCK_2,  // Profile
	BLOCK_3,  // Decks
	BLOCK_4,  // 
	BLOCK_5,  // 
	BLOCK_6   // ?
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



// Pad a newly created file to 64kB with FF bytes.
void ST_PadSav(FILE* out_sav);


typedef struct {
	void*      data;
	STErrCode  errCode;
} ST_SavBlockResult;

typedef struct {
	ST_SavBlockResult  block1;
	ST_SavBlockResult  block2;
	ST_SavBlockResult  block3;
	ST_SavBlockResult  block4;
	ST_SavBlockResult  block5;
	ST_SavBlockResult  block6;
} ST_Sav;

static inline bool ST_SavDataImport(ST_Sav* out_data, FILE* in_sav) {
	out_data->block1.errCode = ST_GetSavBlock1Data(&out_data->block1.data, in_sav);
	out_data->block2.errCode = ST_GetSavBlock2Data(&out_data->block2.data, in_sav);
	out_data->block3.errCode = ST_GetSavBlock3Data(&out_data->block3.data, in_sav);
	out_data->block4.errCode = ST_GetSavBlock4Data(&out_data->block4.data, in_sav);
	out_data->block5.errCode = ST_GetSavBlock5Data(&out_data->block5.data, in_sav);
	out_data->block6.errCode = ST_GetSavBlock6Data(&out_data->block6.data, in_sav);
	
	return (out_data->block1.errCode +
	        out_data->block2.errCode +
	        out_data->block3.errCode +
	        out_data->block4.errCode +
	        out_data->block5.errCode +
	        out_data->block6.errCode) == 0;
}

static inline void ST_SavDataExport(const ST_Sav* in_data, FILE* out_sav) {
	ST_PutSavBlock1Data(out_sav, in_data->block1.data);
	ST_PutSavBlock2Data(out_sav, in_data->block2.data);
	ST_PutSavBlock3Data(out_sav, in_data->block3.data);
	ST_PutSavBlock4Data(out_sav, in_data->block4.data);
	ST_PutSavBlock5Data(out_sav, in_data->block5.data);
	ST_PutSavBlock6Data(out_sav, in_data->block6.data);
	ST_PadSav(out_sav);
}

static inline void ST_SavDataFree(ST_Sav* in_data) {
	free(in_data->block1.data);
	free(in_data->block2.data);
	free(in_data->block3.data);
	free(in_data->block4.data);
	free(in_data->block5.data);
	free(in_data->block6.data);
}


#endif
