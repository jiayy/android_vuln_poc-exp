# CVE-2022-0185

This repo contains demo exploits for CVE-2022-0185. There are two versions here. 

The non-kctf version (fuse version) specifically targets Ubuntu with kernel version 5.11.0-44. It does not directly return a root shell, but makes /bin/bash suid, which will lead to trivial privilege escalation.  Adjusting the `single_start` and `modprobe_path` offsets should allow it to work on most other Ubuntu versions that have kernel version 5.7 or higher; for versions between 5.1 and 5.7, the spray will need to be improved as in the kctf version. The exploitation strategy relies on FUSE and SYSVIPC elastic objects to achieve arbitrary write. 

The kctf version achieves RCE as the root user in the root namespace, but has at most 50% reliability - it is targeted towards Kubernetes 1.22 (1.22.3-gke.700). This exploitation strategy relies on pipes and SYSVIPC elastic objects to trigger a stack pivot and execute a ROP chain in kernelspace.

[demo against Ubuntu with kernel version 5.13.0-25](https://twitter.com/ryaagard/status/1483592308352294917)

[demo against Google kCTF Infrastructure](https://twitter.com/clubby789/status/1484646192990543883)

[exploitation writeup](https://www.willsroot.io/2022/01/cve-2022-0185.html)
