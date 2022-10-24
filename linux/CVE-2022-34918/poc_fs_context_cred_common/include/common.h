#pragma once

#include <unistd.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE (0x1000)
#endif

#define FILENAME_MAX_LEN 0x80

void init_namespace(void);
void set_cpu_affinity(int cpu_n, pid_t pid);
char *generate_tmp_filename(void);

void hexdump(const void *data, size_t size);