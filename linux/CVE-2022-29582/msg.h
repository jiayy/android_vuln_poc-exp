#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif

#ifndef MSG_H
#define MSG_H

#include <sys/msg.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>

#include "err_state.h"

#define TOTAL_MSGS      (9999)
#define MSG_SIZE        (4500)

struct msgb {
    long mtype;
    char mtext[1];
};


err_t pre_spray_msg(int64_t*, uint32_t);
err_t spray_msg(uint64_t*, uint32_t, char*, uint64_t);
err_t leak_msg(uint64_t, uint64_t*, uint32_t, char*, uint64_t);
void free_msg(uint64_t *store, uint32_t amount, uint64_t size);

#endif // MSG_H