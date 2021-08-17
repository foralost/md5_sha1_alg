/*
 * main.c
 *
 *  Created on: 8 sie 2021
 *      Author: foralost
 */
#include <stdio.h>

#include "include/md5_lib.h"
#include "include/sha256_lib.h"

int main(int argc, char** argv, char** envp)
{
	char example[] = "abc";
	size_t length = 3;

	struct sha256_context dest;
	sha256_digest(example, length, &dest);

	char out[32];

	sha256_convert_char(out, &dest);
	printf("SHA256 \n");
	for( int i = 0 ; i< 32; i++){
		printf("%hhX", out[i]);
	}

	return 0;
}

