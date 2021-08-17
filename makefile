all:
	gcc -Wall -Wextra -Wpedantic -g -lm -c -o src/include/obj/libsha256.a src/include/sha256_lib.c
	gcc -Wall -Wextra -Wpedantic -g -lm -c -o src/include/obj/libmd5.a src/include/md5_lib.c
	gcc -g -lm -lmd5 -lsha256 -Lsrc/include/obj -o bin/md5_sha256 src/main.c 
