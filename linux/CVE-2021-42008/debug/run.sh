# qemu-img create debian.qcow2 10G
# wget https://cdimage.debian.org/mirror/cdimage/archive/bullseye_di_rc3/amd64/iso-cd/debian-bullseye-DI-rc3-amd64-netinst.iso 

qemu-system-x86_64 \
	-s \
	#-cdrom debian-bullseye-DI-rc3-amd64-netinst.iso \
	-cpu qemu64,+smap,+smep,+rdrand \
        -drive "file=../debian.qcow2,format=qcow2" \
        -m 4G \
        -smp 4 \
	-vga virtio \
	-serial mon:stdio \
	-nographic \
	-enable-kvm

