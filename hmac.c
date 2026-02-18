#include "hmac.h"
#include "sha1.h"

#include <stdlib.h>
#include <string.h>

static void prepareKeysSha1(const void* in_key, size_t length, void** out_i_key, void** out_o_key);


#define SHA1_BLOCKSIZE  (64)
void HMAC_SHA1_Calc(void* dst, const void* input, size_t input_len, const void* key, size_t key_len) {
	void* i_key;
	void* o_key;
	prepareKeysSha1(key, key_len, &i_key, &o_key);
	
	uint8_t tmp_hash[SHA1_DIGEST_SIZE];
	
	SHA1_Ctx sha;
	
	SHA1_Init(&sha);
	SHA1_Update(&sha, i_key, SHA1_BLOCKSIZE);
	SHA1_Update(&sha, input, input_len);
	SHA1_Digest(&sha, &tmp_hash[0]);
	
	SHA1_Init(&sha);
	SHA1_Update(&sha, o_key, SHA1_BLOCKSIZE);
	SHA1_Update(&sha, &tmp_hash[0], SHA1_DIGEST_SIZE);
	SHA1_Digest(&sha, dst);
	
	free(i_key);
	free(o_key);
}



static void prepareKeysSha1(const void* in_key, size_t length, void** out_i_key, void** out_o_key) {
	uint8_t* i_key = calloc(1, SHA1_BLOCKSIZE);
	uint8_t* o_key = malloc(SHA1_BLOCKSIZE);
	
	if (length > SHA1_BLOCKSIZE) {
		SHA1_Calc(i_key, in_key, length);
	} else {
		memcpy(i_key, in_key, length);
	}
	
	for (int i = 0; i < SHA1_BLOCKSIZE; i++) {
		o_key[i] = i_key[i] ^ 0x5C;
		i_key[i] ^= 0x36;
	}
	
	*out_i_key = i_key;
	*out_o_key = o_key;
}