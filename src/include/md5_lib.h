/*
 * md5_lib.h
 *
 *  Created on: 8 sie 2021
 *      Author: foralost
 */

#ifndef INCLUDE_MD5_LIB_H_
#define INCLUDE_MD5_LIB_H_

#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <math.h>
#include <stdio.h>

struct md5_context {
	uint32_t A;
	uint32_t B;
	uint32_t C;
	uint32_t D;
};

void md5_digest(const char *source, size_t length,
		struct md5_context *destination);

void md5_convert_char(char* dest, const struct md5_context* src);


#endif /* INCLUDE_MD5_LIB_H_ */
