#pragma once

#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SPRAY_FS_CONTEXT_CNT (0x100)

#ifndef __NR_fsconfig
#define __NR_fsconfig 431
#endif
#ifndef __NR_fsopen
#define __NR_fsopen 430
#endif
#define FSCONFIG_SET_STRING 1

static inline long fsopen(char *name, int flags) {
    return syscall(__NR_fsopen, name, flags);
}

static inline long fsconfig(int fd, unsigned int cmd, char *key, char *value, int aux) {
    return syscall(__NR_fsconfig, fd, cmd, key, value, aux);
}

void spray_fs_context(int *fd_buffer, int spray_size);

void close_fds(int *fd_buffer, int spray_size);