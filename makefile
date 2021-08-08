all:
	gcc -Wall -Wextra -Wpedantic -g -lm -c -o src/include/obj/libmd5.a src/include/md5_lib.c
	gcc -g -lm -lmd5 -Lsrc/include/obj -o bin/md5 src/main.c 
