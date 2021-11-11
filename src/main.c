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
	char example[] = "SsyxTHVieKVWFi1HnBfO4d4SCTtUIZxGf5L31cdWpv8ChJ2Y0LuoEBeaBFiEGYADIVBdKInI3ZH7bR7RspknEk2kzZ12uVk2jFOcr4IZCHoeCVmvmpcowIPwGgHOoMpM";
	struct md5_context ctx;
	md5_digest(example, 128, &ctx);
	return 0;
}

