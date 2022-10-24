kctf:
	gcc -no-pie -static exploit_kctf.c util.c -o exploit -masm=intel -pthread
	strip exploit

fuse:
	gcc -no-pie -static exploit_fuse.c fakefuse.c util.c -I./libfuse libfuse3.a -o exploit -masm=intel -pthread
	strip exploit

