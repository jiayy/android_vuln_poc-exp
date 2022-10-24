#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "fsopen_spray.h"
#include "log.h"

void spray_fs_context(int *fd_buffer, int spray_size) {
    for (int i = 0; i < spray_size; i++) {
        fd_buffer[i] = fsopen("ext4", 0);
        if (fd_buffer[i] < 0) {
            die("fsopen: %m");
        }
    }
}

void close_fds(int *fd_buffer, int spray_size) {
    for (int i = 0; i < spray_size; i++) {
        if (fd_buffer[i]) {
            close(fd_buffer[i]);
        }
    }
}