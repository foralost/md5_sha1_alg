/*
 * md5_lib.c
 *
 *  Created on: 8 sie 2021
 *      Author: foralost
 */

#include "md5_lib.h"

#define 	MD5_SIN_TABLE_SIZE 			64
#define 	MD5_HASH_LENGTH 			512
#define 	MD5_MANDATORY_CONGRUENT		56
#define 	MD5_MODULO					64
#define		MD5_APPEND_BYTE				0x80

#define 	MD5_START_VAL_A				0x67452301
#define 	MD5_START_VAL_B				0xefcdab89
#define 	MD5_START_VAL_C				0x98badcfe
#define 	MD5_START_VAL_D				0x10325476

#define 	MD5_BLOCK_SIZE				512
#define 	MD5_ROUND_SIZE				16
#define 	MD5_ROUND_COUNT				4

const char __md5_rotation_constants[4][4] = { { 7, 12, 17, 22 },
		{ 5, 9, 14, 20 }, { 4, 11, 16, 23 }, { 6, 10, 15, 21 } };

const char __md5_round_table[4][4] = { { 7, 12, 17, 22 }, { 5, 9, 14, 20 }, { 4,
		11, 16, 23 }, { 6, 10, 15, 21 } };

uint32_t __md5_sin_table[MD5_SIN_TABLE_SIZE] = { 0 };

// ---------- STUBS -----------
void __md5_update_sinus_table(void);

void __md5_prepare_msg(const char *src, const size_t length, char **dst,
		size_t *new_length);

uint32_t __md5_rotate_left(const uint32_t val, const uint8_t n);

void __md5_process_block(const char *block, struct md5_context *current_context);

// -------------- CODE SECTION --------------------

uint32_t __md5_rotate_left(const uint32_t val, const uint8_t n) {
	return ((val << n) | (val >> (sizeof(val) * 8 - n)));
}
void __md5_process_block(const char *block, struct md5_context *ctx) {

	const uint32_t *work_cnvrt = (const uint32_t*) block;
	uint32_t f_val;
	uint8_t offset;

	for (uint8_t i = 0; i < MD5_ROUND_SIZE * MD5_ROUND_COUNT; i++) {

		switch (i >> MD5_ROUND_COUNT) {

		case 0:
			f_val = (ctx->B & ctx->C) | ((~ctx->B) & ctx->D);
			offset = i;
			break;

		case 1:
			f_val = (ctx->D & ctx->B) | ((~ctx->D) & ctx->C);
			offset = (5 * i + 1) & 0x0F;
			break;
		case 2:
			f_val = ctx->B ^ ctx->C ^ ctx->D;
			offset = (3 * i + 5) & 0x0F;
			break;

		case 3:
			f_val = ctx->C ^ (ctx->B | (~ctx->D));
			offset = (7 * i) & 0x0F;
			break;

		default:
			f_val = 0;
		}

		f_val += ctx->A + __md5_sin_table[i] + work_cnvrt[offset];

		ctx->A = ctx->D;
		ctx->D = ctx->C;
		ctx->C = ctx->B;

		ctx->B += __md5_rotate_left(f_val,
				__md5_rotation_constants[i >> 4][i & 3]);
	}
}

void md5_digest(const char *source, const size_t length,
		struct md5_context *destination) {

	if (!__md5_sin_table[0])
		__md5_update_sinus_table();

	struct md5_context start_context;
	struct md5_context block_context;

	start_context.A = MD5_START_VAL_A;
	start_context.B = MD5_START_VAL_B;
	start_context.C = MD5_START_VAL_C;
	start_context.D = MD5_START_VAL_D;

	char *szWorkArea;
	size_t new_length;

	__md5_prepare_msg(source, length, &szWorkArea, &new_length);

	const size_t count_blocks = new_length >> 6; // Count of 512 blocks...

	for (size_t i = 0; i < count_blocks; i++) {
		block_context = start_context;

		__md5_process_block(szWorkArea + i * MD5_BLOCK_SIZE, &block_context);

		start_context.A += block_context.A;
		start_context.B += block_context.B;
		start_context.C += block_context.C;
		start_context.D += block_context.D;
	}

	*destination = start_context;
	free(szWorkArea);
}

void __md5_update_sinus_table() {
	for (int i = 0; i < MD5_SIN_TABLE_SIZE; i++) {
		const double sin_val = fabs(sin(i + 1));
		const uint64_t maxVal = (uint64_t) UINT32_MAX + (uint64_t) 1;
		__md5_sin_table[i] = floor((double) maxVal * sin_val);
	}
}

void __md5_prepare_msg(const char *src, const size_t length, char **dst,
		size_t *new_length) {
	/*
	 * Extra bytes for sure:
	 *	1 byte for 0x80
	 *	x bytes to be congruent to 448 mod 512 (bits = 64 bytes)
	 *	8 bytes for original length
	 *		finally: 1 + x + 8
	 *
	 *	Cheat table: 448 bits = 56 bytes
	 *				 512 bits = 64 bytes = 2^6 bytes
	 */

	size_t newLength = length + 1; // 1 Additional byte (0x80)
	uint8_t restModulo = newLength & 0x3F; // Canceling everything but last 6 bits
	int8_t diff = 0;

	if (restModulo != MD5_MANDATORY_CONGRUENT) {
		diff = MD5_MANDATORY_CONGRUENT - restModulo;

		if (diff < 0)
			diff += MD5_MODULO;
	}
	newLength += diff + 8;
	*dst = malloc(newLength);

	memcpy(*dst, src, length);

	(*dst)[length] = (uint8_t) MD5_APPEND_BYTE;

	for (int8_t i = 0; i < diff; i++) {
		(*dst)[length + 1 + i] = 0;
	}

	size_t bitsLength = length << 3;
	char *lengthCnvrt = (char*) &bitsLength;

	for (uint8_t i = 0; i < sizeof(bitsLength); i++) {
		(*dst)[newLength - sizeof(bitsLength) + i] = lengthCnvrt[i];
	}

	*new_length = newLength;
}

void __md5_uint32_to_char(char *dest, uint32_t val) {

	dest[0] = (uint8_t) (val);
	dest[1] = (uint8_t) (val >> 8);
	dest[2] = (uint8_t) (val >> 16);
	dest[3] = (uint8_t) (val >> 24);

}
void md5_convert_char(char *dest, const struct md5_context *src) {

	__md5_uint32_to_char(dest, src->A);
	__md5_uint32_to_char(dest + 4, src->B);
	__md5_uint32_to_char(dest + 8, src->C);
	__md5_uint32_to_char(dest + 12, src->D);

}
