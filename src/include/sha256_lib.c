/*
 * sha256_lib.c
 *
 *  Created on: 11 sie 2021
 *      Author: foralost
 */

#include "sha256_lib.h"

#define 	SHA256_START_VAL_A	0x6a09e667
#define 	SHA256_START_VAL_B	0xbb67ae85
#define 	SHA256_START_VAL_C	0x3c6ef372
#define 	SHA256_START_VAL_D	0xa54ff53a
#define 	SHA256_START_VAL_E	0x510e527f
#define 	SHA256_START_VAL_F	0x9b05688c
#define 	SHA256_START_VAL_G	0x1f83d9ab
#define 	SHA256_START_VAL_H	0x5be0cd19

#define 	SHA256_HASH_LENGTH 				128
#define 	SHA256_MANDATORY_CONGRUENT		56
#define 	SHA256_MODULO					64
#define		SHA256_APPEND_BYTE				0x80

#define		SHA256_BLOCK_SIZE				512

uint32_t __sha256_round_constants[64] = { 0 };

// --- STUBS ---
void __sha256_generate_constants();

void sha256_digest(const char *src, size_t length, struct sha256_context *ctx);

uint64_t __sha256_calc_constant(uint16_t prime);

void __sha256_process_block(const char *block,
		struct sha256_context *current_context);

void __sha256_prepare_msg(const char *src, size_t length, char **dest,
		size_t *new_length);

uint32_t __sha256_right_rotate(uint32_t val, uint8_t n);

void __sha256_block_swap_endianness(char *src);

// --- CODE SECTION ---

void sha256_digest(const char *src, size_t length,
		struct sha256_context *destination) {
	if (!__sha256_round_constants[0])
		__sha256_generate_constants();

	struct sha256_context start_context;
	struct sha256_context block_context;

	start_context.A = SHA256_START_VAL_A;
	start_context.B = SHA256_START_VAL_B;
	start_context.C = SHA256_START_VAL_C;
	start_context.D = SHA256_START_VAL_D;
	start_context.E = SHA256_START_VAL_E;
	start_context.F = SHA256_START_VAL_F;
	start_context.G = SHA256_START_VAL_G;
	start_context.H = SHA256_START_VAL_H;

	char *szWorkArea;
	size_t new_length;

	__sha256_prepare_msg(src, length, &szWorkArea, &new_length);

	const size_t count_blocks = new_length >> 6; // Count of 512 blocks...

	for (size_t i = 0; i < count_blocks; i++) {
		block_context = start_context;
		__sha256_block_swap_endianness(szWorkArea + i * SHA256_BLOCK_SIZE);
		__sha256_process_block(szWorkArea + i * SHA256_BLOCK_SIZE,
				&block_context);

		start_context.A += block_context.A;
		start_context.B += block_context.B;
		start_context.C += block_context.C;
		start_context.D += block_context.D;
		start_context.E += block_context.E;
		start_context.F += block_context.F;
		start_context.G += block_context.G;
		start_context.H += block_context.H;
	}

	*destination = start_context;
	free(szWorkArea);
}

void __sha256_s_functions(uint32_t *n1, uint32_t *n2, uint32_t *s0,
		uint32_t *s1) {
	*s0 = (__sha256_right_rotate((*n1), 7)) ^ (__sha256_right_rotate((*n1), 18))
			^ ((*n1) >> 3);
	*s1 = (__sha256_right_rotate((*n2), 17))
			^ (__sha256_right_rotate((*n2), 19)) ^ ((*n2) >> 10);
}

uint32_t __sha256_right_rotate(uint32_t val, uint8_t n) {
	return ((val >> n) | (val << (sizeof(val) * 8 - n)));
}

void __sha256_process_block(const char *block, struct sha256_context *ctx) {
	uint32_t work_area[64];
	uint32_t s0;
	uint32_t s1;

	memcpy(work_area, block, sizeof(uint32_t) * 16);

	for (uint8_t i = 16; i < 64; i++) {
		__sha256_s_functions(work_area + (i - 15), work_area + (i - 2), &s0,
				&s1);

		work_area[i] = work_area[i - 16] + s0 + work_area[i - 7] + s1;
	}

	for (uint8_t i = 0; i < 64; i++) {
		s1 = __sha256_right_rotate(ctx->E, 6)
				^ __sha256_right_rotate(ctx->E, 11)
				^ __sha256_right_rotate(ctx->E, 25);

		uint32_t ch = (ctx->E & ctx->F) ^ ((~ctx->E) & ctx->G);

		uint32_t tmp_1 = ctx->H + s1 + ch + __sha256_round_constants[i]
				+ work_area[i];

		s0 = __sha256_right_rotate(ctx->A, 2)
				^ __sha256_right_rotate(ctx->A, 13)
				^ __sha256_right_rotate(ctx->A, 22);

		uint32_t maj = (ctx->A & ctx->B) ^ (ctx->A & ctx->C)
				^ (ctx->B & ctx->C);

		uint32_t tmp_2 = s0 + maj;

		//Cycle continues...
		ctx->H = ctx->G;
		ctx->G = ctx->F;
		ctx->F = ctx->E;
		ctx->E = ctx->D + tmp_1;
		ctx->D = ctx->C;
		ctx->C = ctx->B;
		ctx->B = ctx->A;
		ctx->A = tmp_1 + tmp_2;
	}

}

uint64_t __sha256_calc_constant(uint16_t prime) {
	double db_prime = pow(prime, 1 / 3.);
	db_prime = db_prime - floor(db_prime);

	uint64_t trick = *(uint64_t*) &db_prime;
	trick += 0x0200000000000000;
	db_prime = *(double*) &trick;
	return (uint64_t) floor(db_prime);
}

void __sha256_generate_constants() {
	// First 64 primes
	uint16_t primes[] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
			47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
			127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191,
			193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263,
			269, 271, 277, 281, 283, 293, 307, 311 };

	for (uint8_t i = 0; i < 64; i++) {
		__sha256_round_constants[i] = (uint32_t) __sha256_calc_constant(
				primes[i]);
	}
}

// Same as MD5
void __sha256_prepare_msg(const char *src, const size_t length, char **dst,
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

	if (restModulo != SHA256_MANDATORY_CONGRUENT) {
		diff = SHA256_MANDATORY_CONGRUENT - restModulo;

		if (diff < 0)
			diff += SHA256_MODULO;
	}
	newLength += diff + 8;
	*dst = malloc(newLength);

	memcpy(*dst, src, length);

	(*dst)[length] = (uint8_t) SHA256_APPEND_BYTE;

	for (int8_t i = 0; i < diff; i++) {
		(*dst)[length + 1 + i] = 0;
	}

	size_t bitsLength = length << 3;
	char *lengthCnvrt = (char*) &bitsLength;

	for (uint8_t i = 0; i < sizeof(bitsLength); i++) {
		(*dst)[newLength - sizeof(bitsLength) + i] = lengthCnvrt[7 - i];
	}

	*new_length = newLength;
}
//Only for UINT32
void __sha256_block_swap_endianness(char *src) {
	uint32_t placeholder = 0;
	uint32_t *work_area = (uint32_t*) src;
	for (uint8_t i = 0; i < 16; i++) {

		placeholder = work_area[i];
		if (placeholder) {
			placeholder = ((placeholder >> 24))
					| ((placeholder << 8) & 0x00FF0000) | // move byte 1 to byte 2
					((placeholder >> 8) & 0x0000FF00) | // move byte 2 to byte 1
					((placeholder << 24));
			work_area[i] = placeholder;
		}
	}

}
void __sha256_uint32_to_char(char *dest, uint32_t val) {

	dest[3] = (uint8_t) (val);
	dest[2] = (uint8_t) (val >> 8);
	dest[1] = (uint8_t) (val >> 16);
	dest[0] = (uint8_t) (val >> 24);

}
void sha256_convert_char(char *dest, const struct sha256_context *src) {

	__sha256_uint32_to_char(dest, src->A);
	__sha256_uint32_to_char(dest + 4, src->B);
	__sha256_uint32_to_char(dest + 8, src->C);
	__sha256_uint32_to_char(dest + 12, src->D);
	__sha256_uint32_to_char(dest + 16, src->E);
	__sha256_uint32_to_char(dest + 20, src->F);
	__sha256_uint32_to_char(dest + 24, src->G);
	__sha256_uint32_to_char(dest + 28, src->H);
}

