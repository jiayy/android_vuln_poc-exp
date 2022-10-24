#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "log.h"

void init_namespace(void) {
    int fd;
    char buff[0x100];

    uid_t uid = getuid();
    gid_t gid = getgid();

    if (unshare(CLONE_NEWUSER | CLONE_NEWNS)) {
        die("unshare(CLONE_NEWUSER | CLONE_NEWNS): %m");
    }

    if (unshare(CLONE_NEWNET)) {
        die("unshare(CLONE_NEWNET): %m");
    }

    fd = open("/proc/self/setgroups", O_WRONLY);
    snprintf(buff, sizeof(buff), "deny");
    write(fd, buff, strlen(buff));
    close(fd);

    fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(buff, sizeof(buff), "0 %d 1", uid);
    write(fd, buff, strlen(buff));
    close(fd);

    fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(buff, sizeof(buff), "0 %d 1", gid);
    write(fd, buff, strlen(buff));
    close(fd);
}

void set_cpu_affinity(int cpu_n, pid_t pid) {
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu_n, &set);

    if (sched_setaffinity(pid, sizeof(set), &set) < 0) {
        die("sched_setaffinity: %m");
    }
}

void hexdump(const void *data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        dprintf(2, "%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            dprintf(2, " ");
            if ((i + 1) % 16 == 0) {
                dprintf(2, "|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    dprintf(2, " ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    dprintf(2, "   ");
                }
                dprintf(2, "|  %s \n", ascii);
            }
        }
    }
}
