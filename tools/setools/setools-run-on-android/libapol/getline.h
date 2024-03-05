/* Replacement for getline(3) which is absent in bionic. */

#ifndef __GETLINE_H__
#define __GETLINE_H__

#include <stdio.h>

ssize_t apol_getline(char **lineptr, size_t *n, FILE *stream);

#endif /* __GETLINE_H__ */
