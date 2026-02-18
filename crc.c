#include "crc.h"


uint32_t CRC32(void* input, size_t length) {
	uint8_t* input_bytes = (uint8_t*)input;
	uint32_t crc = 0xFFFFFFFF;
	uint32_t poly = 0xEDB88320;
	while (length--) {
		crc ^= *input_bytes++;
		for (int i = 0; i < 8; i++) {
			if (crc & 1) {
				crc = poly ^ (crc >> 1);
			} else {
				crc = (crc >> 1);
			}
		}
	}
	
	return ~crc;
}
