#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
	uint32_t  h[5];
	uint8_t   buffer[64];
	size_t    bufferLength;
	struct {
		uint32_t  high;
		uint32_t  low;
	}  bitsRead;
} SHA1_Ctx;

void SHA1_Init(SHA1_Ctx* ctx);
void SHA1_Update(SHA1_Ctx* ctx, const void* input, size_t length);
void SHA1_Digest(SHA1_Ctx* ctx, void* dst);

static inline void SHA1_Calc(void* dst, const void* input, size_t length) {
	SHA1_Ctx sha1;
	SHA1_Init(&sha1);
	SHA1_Update(&sha1, input, length);
	SHA1_Digest(&sha1, dst);
}

#define SHA1_DIGEST_SIZE  (20)

#endif
