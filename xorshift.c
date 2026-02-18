#include "xorshift.h"


void XorShift_Seed(XorShift_Ctx* ctx, uint32_t seed) {
	ctx->x[3] = seed;
	ctx->x[2] = 0x159A55E5;
	ctx->x[1] = 0x1F123BB5;
	ctx->x[0] = 0x05491333;
}


uint32_t XorShift_Rand(XorShift_Ctx* ctx) {
	uint32_t tmp1 = ctx->x[3];
	ctx->x[3] = ctx->x[2];
	ctx->x[2] = ctx->x[1];
	ctx->x[1] = ctx->x[0];
	
	uint32_t tmp2 = ctx->x[0];
	tmp2 ^= tmp2 >> 19;
	tmp1 ^= tmp1 << 11;
	tmp1 ^= tmp1 >> 8;
	
	ctx->x[0] = tmp2 ^ tmp1;
	
	return ctx->x[0];
}
