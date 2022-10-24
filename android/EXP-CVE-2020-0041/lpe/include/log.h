#ifndef __LOG_H_
#define __LOG_H_

#include <stdio.h>

#define ALOGE(...) printf(__VA_ARGS__)
#define ALOGI(...) printf(__VA_ARGS__)
ssize_t log_info(const char *format, ...);
ssize_t log_err(const char *format, ...);
#endif
