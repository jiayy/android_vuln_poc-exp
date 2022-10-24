#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sched.h>
#include <pthread.h>
#include <poll.h>
#include <assert.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/sched.h>

typedef struct {
  long mtype;
  char mtext[1];
} msg;

int32_t make_queue(key_t key, int msgflg);
ssize_t get_msg(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
void send_msg(int msqid, void *msgp, size_t msgsz, int msgflg);