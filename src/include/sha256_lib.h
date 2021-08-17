/*
 * sha256_lib.h
 *
 *  Created on: 11 sie 2021
 *      Author: foralost
 */

#ifndef INCLUDE_SHA256_LIB_H_
#define INCLUDE_SHA256_LIB_H_
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <math.h>

struct sha256_context{
	uint32_t A;
	uint32_t B;
	uint32_t C;
	uint32_t D;
	uint32_t E;
	uint32_t F;
	uint32_t G;
	uint32_t H;
};

void sha256_digest(const char* src, size_t length, struct sha256_context* ctx);

void sha256_convert_char(char *dest, const struct sha256_context *src);
#endif /* INCLUDE_SHA256_LIB_H_ */
