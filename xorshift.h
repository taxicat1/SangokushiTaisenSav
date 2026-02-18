#ifndef XORSHIFT_H
#define XORSHIFT_H

#include <stdint.h>

typedef struct {
	uint32_t x[4];
} XorShift_Ctx;

void XorShift_Seed(XorShift_Ctx* ctx, uint32_t seed);
uint32_t XorShift_Rand(XorShift_Ctx* ctx);

#endif
