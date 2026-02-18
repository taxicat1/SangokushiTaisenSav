#include "sha1.h"

#include <string.h>

static void processBlock(SHA1_Ctx* ctx, const void* external_src);
static void finalize(SHA1_Ctx* ctx);


#define SHA1_CONST_1  (0x67452301)
#define SHA1_CONST_2  (0xEFCDAB89)
#define SHA1_CONST_3  (0x98BADCFE)
#define SHA1_CONST_4  (0x10325476)
#define SHA1_CONST_5  (0xC3D2E1F0)
void SHA1_Init(SHA1_Ctx* ctx) {
	ctx->h[0] = SHA1_CONST_1;
	ctx->h[1] = SHA1_CONST_2;
	ctx->h[2] = SHA1_CONST_3;
	ctx->h[3] = SHA1_CONST_4;
	ctx->h[4] = SHA1_CONST_5;
	
	ctx->bufferLength  = 0;
	ctx->bitsRead.high = 0;
	ctx->bitsRead.low  = 0;
}


#define BUFFER_SIZE  (64)
void SHA1_Update(SHA1_Ctx* ctx, const void* input, size_t length) {
	uint8_t* input_bytes = (uint8_t*)input;
	
	uint32_t added_bits_low  = length << 3;
	uint32_t added_bits_high = length >> 29;
	
	if (ctx->bitsRead.low > (0xFFFFFFFF - added_bits_low)) {
		added_bits_high++;
	}
	
	ctx->bitsRead.high += added_bits_high;
	ctx->bitsRead.low  += added_bits_low;
	
	if (ctx->bufferLength + length < BUFFER_SIZE) {
		memcpy(&ctx->buffer[ctx->bufferLength], input_bytes, length);
		ctx->bufferLength += length;
	} else {
		if (ctx->bufferLength > 0) {
			int copy_bytes = BUFFER_SIZE - ctx->bufferLength;
			memcpy(&ctx->buffer[ctx->bufferLength], input_bytes, copy_bytes);
			length -= copy_bytes;
			input_bytes += copy_bytes;
			
			processBlock(ctx, NULL);
			ctx->bufferLength = 0;
		}
		
		while (length >= BUFFER_SIZE) {
			processBlock(ctx, input_bytes);
			length -= BUFFER_SIZE;
			input_bytes += BUFFER_SIZE;
		}
		
		if (length != 0) {
			memcpy(&ctx->buffer[0], input_bytes, length);
			ctx->bufferLength = length;
		}
	}
}


void SHA1_Digest(SHA1_Ctx* ctx, void* dst) {
	finalize(ctx);
	uint8_t* output = (uint8_t*)dst;
	for (int i = 0; i < 5; i++) {
		*output++ = ctx->h[i] >> 24;
		*output++ = ctx->h[i] >> 16;
		*output++ = ctx->h[i] >> 8;
		*output++ = ctx->h[i];
	}
}


static inline uint32_t readU32BE(uint8_t* src) {
	uint32_t ret = *src++ << 24;
	ret |= *src++ << 16;
	ret |= *src++ << 8;
	ret |= *src;
	return ret;
}


#define ROTL(x, amt) (((x) << (amt)) | ((x) >> (32 - (amt))))
#define FUNC_CH(b, c, d)  ((b & c) | (~b & d))
#define FUNC_SUM(b, c, d)  (b ^ c ^ d)
#define FUNC_MAJ(b, c, d)  ((b & c) | (d & (b ^ c)))
#define K_1  (0x5A827999)
#define K_2  (0x6ED9EBA1)
#define K_3  (0x8F1BBCDC)
#define K_4  (0xCA62C1D6)
static void processBlock(SHA1_Ctx* ctx, const void* external_src) {
	uint8_t* buffer;
	if (external_src != NULL) {
		buffer = (uint8_t*)external_src;
	} else {
		buffer = &ctx->buffer[0];
	}
	
	uint32_t X[80];
	for (int i = 0; i < 16; i++) {
		X[i] = readU32BE(buffer + (i * 4));
	}
	
	for (int i = 16; i < 80; i++) {
		uint32_t sum = X[i - 3] ^ X[i - 8] ^ X[i - 14] ^ X[i - 16];
		X[i] = ROTL(sum, 1);
	}
	
	uint32_t a = ctx->h[0];
	uint32_t b = ctx->h[1];
	uint32_t c = ctx->h[2];
	uint32_t d = ctx->h[3];
	uint32_t e = ctx->h[4];
	
	uint32_t* Xp = &X[0];
	
	for (int i = 0; i < 4; i++) {
		e += FUNC_CH(b, c, d) + ROTL(a, 5) + *Xp++ + K_1;  b = ROTL(b, 30);
		d += FUNC_CH(a, b, c) + ROTL(e, 5) + *Xp++ + K_1;  a = ROTL(a, 30);
		c += FUNC_CH(e, a, b) + ROTL(d, 5) + *Xp++ + K_1;  e = ROTL(e, 30);
		b += FUNC_CH(d, e, a) + ROTL(c, 5) + *Xp++ + K_1;  d = ROTL(d, 30);
		a += FUNC_CH(c, d, e) + ROTL(b, 5) + *Xp++ + K_1;  c = ROTL(c, 30);
	}
	
	for (int i = 0; i < 4; i++) {
		e += FUNC_SUM(b, c, d) + ROTL(a, 5) + *Xp++ + K_2;  b = ROTL(b, 30);
		d += FUNC_SUM(a, b, c) + ROTL(e, 5) + *Xp++ + K_2;  a = ROTL(a, 30);
		c += FUNC_SUM(e, a, b) + ROTL(d, 5) + *Xp++ + K_2;  e = ROTL(e, 30);
		b += FUNC_SUM(d, e, a) + ROTL(c, 5) + *Xp++ + K_2;  d = ROTL(d, 30);
		a += FUNC_SUM(c, d, e) + ROTL(b, 5) + *Xp++ + K_2;  c = ROTL(c, 30);
	}
	
	for (int i = 0; i < 4; i++) {
		e += FUNC_MAJ(b, c, d) + ROTL(a, 5) + *Xp++ + K_3;  b = ROTL(b, 30);
		d += FUNC_MAJ(a, b, c) + ROTL(e, 5) + *Xp++ + K_3;  a = ROTL(a, 30);
		c += FUNC_MAJ(e, a, b) + ROTL(d, 5) + *Xp++ + K_3;  e = ROTL(e, 30);
		b += FUNC_MAJ(d, e, a) + ROTL(c, 5) + *Xp++ + K_3;  d = ROTL(d, 30);
		a += FUNC_MAJ(c, d, e) + ROTL(b, 5) + *Xp++ + K_3;  c = ROTL(c, 30);
	}
	
	for (int i = 0; i < 4; i++) {
		e += FUNC_SUM(b, c, d) + ROTL(a, 5) + *Xp++ + K_4;  b = ROTL(b, 30);
		d += FUNC_SUM(a, b, c) + ROTL(e, 5) + *Xp++ + K_4;  a = ROTL(a, 30);
		c += FUNC_SUM(e, a, b) + ROTL(d, 5) + *Xp++ + K_4;  e = ROTL(e, 30);
		b += FUNC_SUM(d, e, a) + ROTL(c, 5) + *Xp++ + K_4;  d = ROTL(d, 30);
		a += FUNC_SUM(c, d, e) + ROTL(b, 5) + *Xp++ + K_4;  c = ROTL(c, 30);
	}
	
	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;
}

static void finalize(SHA1_Ctx* ctx) {
	ctx->buffer[ctx->bufferLength] = 0x80;
	ctx->bufferLength++;
	
	if (ctx->bufferLength > 56) {
		memset(&ctx->buffer[ctx->bufferLength], 0x00, 64 - ctx->bufferLength);
		processBlock(ctx, NULL);
		ctx->bufferLength = 0;
	}
	
	memset(&ctx->buffer[ctx->bufferLength], 0x00, 56 - ctx->bufferLength);
	
	ctx->buffer[56] = ctx->bitsRead.high >> 24;
	ctx->buffer[57] = ctx->bitsRead.high >> 16;
	ctx->buffer[58] = ctx->bitsRead.high >> 8;
	ctx->buffer[59] = ctx->bitsRead.high;
	
	ctx->buffer[60] = ctx->bitsRead.low >> 24;
	ctx->buffer[61] = ctx->bitsRead.low >> 16;
	ctx->buffer[62] = ctx->bitsRead.low >> 8;
	ctx->buffer[63] = ctx->bitsRead.low;
	
	processBlock(ctx, NULL);
	ctx->bufferLength = 0;
}
