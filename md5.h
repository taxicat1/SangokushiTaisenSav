#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
	uint32_t  h[4];
	uint8_t   buffer[64];
	size_t    bufferLength;
	struct {
		uint32_t  high;
		uint32_t  low;
	}  bitsRead;
} MD5_Ctx;

void MD5_Init(MD5_Ctx* ctx);
void MD5_Update(MD5_Ctx* ctx, const void* input, size_t length);
void MD5_Digest(MD5_Ctx* ctx, void* dst);

static inline void MD5_Calc(void* dst, const void* input, size_t length) {
	MD5_Ctx md5;
	MD5_Init(&md5);
	MD5_Update(&md5, input, length);
	MD5_Digest(&md5, dst);
}

#define MD5_DIGEST_SIZE  (16)

#endif
