#include "md5.h"

#include <string.h>

static void processBlock(MD5_Ctx* ctx, const void* external_src);
static void finalize(MD5_Ctx* ctx);


#define MD5_CONST_1  (0x67452301)
#define MD5_CONST_2  (0xEFCDAB89)
#define MD5_CONST_3  (0x98BADCFE)
#define MD5_CONST_4  (0x10325476)
void MD5_Init(MD5_Ctx* ctx) {
	ctx->h[0] = MD5_CONST_1;
	ctx->h[1] = MD5_CONST_2;
	ctx->h[2] = MD5_CONST_3;
	ctx->h[3] = MD5_CONST_4;
	
	ctx->bufferLength  = 0;
	ctx->bitsRead.high = 0;
	ctx->bitsRead.low  = 0;
}


#define BUFFER_SIZE  (64)
void MD5_Update(MD5_Ctx* ctx, const void* input, size_t length) {
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


void MD5_Digest(MD5_Ctx* ctx, void* dst) {
	finalize(ctx);
	uint8_t* output = (uint8_t*)dst;
	for (int i = 0; i < 4; i++) {
		*output++ = ctx->h[i];
		*output++ = ctx->h[i] >> 8;
		*output++ = ctx->h[i] >> 16;
		*output++ = ctx->h[i] >> 24;
	}
}


static inline uint32_t readU32LE(uint8_t* src) {
	uint32_t ret = *src++;
	ret |= *src++ << 8;
	ret |= *src++ << 16;
	ret |= *src << 24;
	return ret;
}


#define ROTL(x, amt) (((x) << (amt)) | ((x) >> (32 - (amt))))
#define FUNC_CH(b, c, d)  ((b & c) | (~b & d))
#define FUNC_CH2(b, c, d)  ((d & b) | (~d & c))
#define FUNC_SUM(b, c, d)  (b ^ c ^ d)
#define FUNC_4(b, c, d)  (c ^ (b | ~d))
static void processBlock(MD5_Ctx* ctx, const void* external_src) {
	static const uint32_t K[64] = {
		0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
		0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
		0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
		0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
		0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
		0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
		0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
		0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
		0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
		0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
		0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
		0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
		0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
		0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
		0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
		0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
	};
	
	uint8_t* buffer;
	if (external_src != NULL) {
		buffer = (uint8_t*)external_src;
	} else {
		buffer = &ctx->buffer[0];
	}
	
	uint32_t X[16];
	for (int i = 0; i < 16; i++) {
		X[i] = readU32LE(buffer + (i * 4));
	}
	
	uint32_t a = ctx->h[0];
	uint32_t b = ctx->h[1];
	uint32_t c = ctx->h[2];
	uint32_t d = ctx->h[3];
	
	const uint32_t* Kp = &K[0];
	
	int j = 0;
	for (int i = 0; i < 4; i++) {
		a += FUNC_CH(b, c, d) + X[j] + *Kp++;  a = ROTL(a,  7);  a += b;  j++;
		d += FUNC_CH(a, b, c) + X[j] + *Kp++;  d = ROTL(d, 12);  d += a;  j++;
		c += FUNC_CH(d, a, b) + X[j] + *Kp++;  c = ROTL(c, 17);  c += d;  j++;
		b += FUNC_CH(c, d, a) + X[j] + *Kp++;  b = ROTL(b, 22);  b += c;  j++;
	}
	j = 1;
	for (int i = 0; i < 4; i++) {
		a += FUNC_CH2(b, c, d) + X[j & 15] + *Kp++;  a = ROTL(a,  5);  a += b;  j += 5;
		d += FUNC_CH2(a, b, c) + X[j & 15] + *Kp++;  d = ROTL(d,  9);  d += a;  j += 5;
		c += FUNC_CH2(d, a, b) + X[j & 15] + *Kp++;  c = ROTL(c, 14);  c += d;  j += 5;
		b += FUNC_CH2(c, d, a) + X[j & 15] + *Kp++;  b = ROTL(b, 20);  b += c;  j += 5;
	}
	j = 5;
	for (int i = 0; i < 4; i++) {
		a += FUNC_SUM(b, c, d) + X[j & 15] + *Kp++;  a = ROTL(a,  4);  a += b;  j += 3;
		d += FUNC_SUM(a, b, c) + X[j & 15] + *Kp++;  d = ROTL(d, 11);  d += a;  j += 3;
		c += FUNC_SUM(d, a, b) + X[j & 15] + *Kp++;  c = ROTL(c, 16);  c += d;  j += 3;
		b += FUNC_SUM(c, d, a) + X[j & 15] + *Kp++;  b = ROTL(b, 23);  b += c;  j += 3;
	}
	j = 0;
	for (int i = 0; i < 4; i++) {
		a += FUNC_4(b, c, d) + X[j & 15] + *Kp++;  a = ROTL(a,  6);  a += b;  j += 7;
		d += FUNC_4(a, b, c) + X[j & 15] + *Kp++;  d = ROTL(d, 10);  d += a;  j += 7;
		c += FUNC_4(d, a, b) + X[j & 15] + *Kp++;  c = ROTL(c, 15);  c += d;  j += 7;
		b += FUNC_4(c, d, a) + X[j & 15] + *Kp++;  b = ROTL(b, 21);  b += c;  j += 7;
	}
	
	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
}


static void finalize(MD5_Ctx* ctx) {
	ctx->buffer[ctx->bufferLength] = 0x80;
	ctx->bufferLength++;
	
	if (ctx->bufferLength > 56) {
		memset(&ctx->buffer[ctx->bufferLength], 0x00, 64 - ctx->bufferLength);
		processBlock(ctx, NULL);
		ctx->bufferLength = 0;
	}
	
	memset(&ctx->buffer[ctx->bufferLength], 0x00, 56 - ctx->bufferLength);
	
	ctx->buffer[56] = ctx->bitsRead.low;
	ctx->buffer[57] = ctx->bitsRead.low >> 8;
	ctx->buffer[58] = ctx->bitsRead.low >> 16;
	ctx->buffer[59] = ctx->bitsRead.low >> 24;
	
	ctx->buffer[60] = ctx->bitsRead.high;
	ctx->buffer[61] = ctx->bitsRead.high >> 8;
	ctx->buffer[62] = ctx->bitsRead.high >> 16;
	ctx->buffer[63] = ctx->bitsRead.high >> 24;
	
	processBlock(ctx, NULL);
	ctx->bufferLength = 0;
}
