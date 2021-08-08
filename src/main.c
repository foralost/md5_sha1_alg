/*
 * main.c
 *
 *  Created on: 8 sie 2021
 *      Author: foralost
 */
#include "include/md5_lib.h"


int main(int argc, char** argv, char** envp)
{
	char example[] = "test123";
	size_t length = 7;

	struct md5_context dest;
	md5_digest(example, length, &dest);

	char out[16];

	md5_convert_char(out, &dest);
	for( int i = 0 ; i< 16; i++){
		printf("%hhX", out[i]);
	}

	return 0;
}

