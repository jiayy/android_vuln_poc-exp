#define _GNU_SOURCE
#include <sched.h>

void pin_cpu(int cpu) {
    cpu_set_t cpuset = {0};
    CPU_SET(cpu, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
}
