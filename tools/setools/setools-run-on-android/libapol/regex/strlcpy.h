/* Replacement for strlcpy(3) which is absent in glibc. */

#ifndef __STRLCPY_H__
#define __STRLCPY_H__

#include <stddef.h> /* size_t */

size_t regex_strlcpy(char *dst, const char *src, size_t dstsize);

#endif /* __STRLCPY_H__ */
