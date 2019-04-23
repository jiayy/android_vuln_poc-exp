mkdir qemu

sudo debootstrap --include=openssh-server,curl,tar,gcc,\
libc6-dev,time,strace,sudo,less,psmisc,\
selinux-utils,policycoreutils,checkpolicy,selinux-policy-default \
stretch qemu


set -eux
 
# Set some defaults and enable promtless ssh to the machine for root.
sudo sed -i '/^root/ { s/:x:/::/ }' qemu/etc/passwd
echo 'T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100' | sudo tee -a qemu/etc/inittab
#printf '\nauto enp0s3\niface enp0s3 inet dhcp\n' | sudo tee -a qemu/etc/network/interfaces
printf '\nallow-hotplug enp0s3\niface enp0s3 inet dhcp\n' | sudo tee -a qemu/etc/network/interfaces
echo 'debugfs /sys/kernel/debug debugfs defaults 0 0' | sudo tee -a qemu/etc/fstab
echo "kernel.printk = 7 4 1 3" | sudo tee -a qemu/etc/sysctl.conf
echo 'debug.exception-trace = 0' | sudo tee -a qemu/etc/sysctl.conf
echo "net.core.bpf_jit_enable = 1" | sudo tee -a qemu/etc/sysctl.conf
echo "net.core.bpf_jit_harden = 2" | sudo tee -a qemu/etc/sysctl.conf
echo "net.ipv4.ping_group_range = 0 65535" | sudo tee -a qemu/etc/sysctl.conf
echo -en "127.0.0.1\tlocalhost\n" | sudo tee qemu/etc/hosts
echo "nameserver 8.8.8.8" | sudo tee -a qemu/etc/resolve.conf
echo "ubuntu" | sudo tee qemu/etc/hostname
sudo mkdir -p qemu/root/.ssh/
rm -rf ssh
mkdir -p ssh
ssh-keygen -f ssh/id_rsa -t rsa -N ''
cat ssh/id_rsa.pub | sudo tee qemu/root/.ssh/authorized_keys
 
# Build a disk image
dd if=/dev/zero of=qemu.img bs=1M seek=2047 count=1
sudo mkfs.ext4 -F qemu.img
sudo mkdir -p /mnt/qemu
sudo mount -o loop qemu.img /mnt/qemu
sudo cp -a qemu/. /mnt/qemu/.
sudo umount /mnt/qemu
