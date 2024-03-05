1. run on linux
1.1 cd setools-run-on-linux
1.2 make setools-build && make setools-install
1.3 adb pull /sys/fs/selinux/policy sepolicy
1.4 sesearch -A -s shell -c file -p write sepolicy 

2. run on android 
1.1 cd setools-run-on-android && make
1.2 adb push libs/arm64-v8a/sesearch /data/local/tmp
1.3 adb shell 

-> on device
	cp /sys/fs/selinux/policy /data/local/tmp/sepolicy
	cd /data/local/tmp
	sesearch -A -s shell -c file -p write  sepolicy 
