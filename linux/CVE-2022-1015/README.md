# CVE-2022-1015

This repository contains a PoC for local privilege escalation of CVE-2022-1015, a bug in the `nf_tables` component of the linux kernel that I found. You can read a detailed analysis of this vulnerability and the exploitation strategy over at my [blog](https://blog.dbouman.nl/2022/04/02/How-The-Tables-Have-Turned-CVE-2022-1015-1016/).

Right now, the exploit is a bit messy. Sorry!

## Affected versions

Kernels after commit 345023b0db31 (v5.12) but before commit 6e1acfa387b9 (v5.17) are vulnerable. 

## Caveats

This exploit is extremely unlikely to pop a root shell for a given vulnerable kernel. You will have to experiment with chain hook locations (input vs output etc.), `nft_bitwise` address leak offsets, and ROP gadget and symbol offsets. I tested on 5.16-rc3+ and had to seriously change my exploit for a kernel build compiled with a different gcc version. 

That said, with all the information given in my blog post I think altering the exploit for a given vulnerable kernel should be doable.

## Building instructions

Simply run `make`, and a `pwn` executable should pop up in the source dir. You will need `libmnl` and `libnftnl` developer packages, as well as linux headers of the target.

You can explicitly specify kernel headers to use with e.g. `make CFLAGS="-I/path/to/linux-tree/usr/include"`.

## Demo

[![](https://asciinema.org/a/zIlTY7p1JRf0y4I8zbGLkpg6H.svg)](https://asciinema.org/a/zIlTY7p1JRf0y4I8zbGLkpg6H)

## Licensing

This code is distributed under the Beerware license. I am not legally responsible for anything you do with it.
