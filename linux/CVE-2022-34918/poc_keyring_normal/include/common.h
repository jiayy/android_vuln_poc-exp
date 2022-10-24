#pragma once

#include <unistd.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE (0x1000)
#endif

void init_namespace(void);
void set_cpu_affinity(int cpu_n, pid_t pid);
void hexdump(const void *data, size_t size);