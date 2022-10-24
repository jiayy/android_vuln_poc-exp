#!/bin/bash -x

clang shellcode.c -masm=intel -S -o shellcode.s \
    -nostdlib -shared -Oz -fpic -fomit-frame-pointer \
    -fno-exceptions -fno-asynchronous-unwind-tables \
    -fno-unwind-tables -fcf-protection=none && \
sed -i "s/.addrsig//g" shellcode.s && \
sed -i '/.section/d' shellcode.s && \
sed -i '/.p2align/d' shellcode.s && \
as --64 -o shellcode.o shellcode.s && \
ld --oformat binary -o shellcode shellcode.o --omagic && \
xxd -i shellcode