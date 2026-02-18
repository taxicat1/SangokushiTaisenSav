#ifndef HMAC_H
#define HMAC_H

#include <stddef.h>

void HMAC_SHA1_Calc(void* dst, const void* input, size_t input_len, const void* key, size_t key_len);

#endif
