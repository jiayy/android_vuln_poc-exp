/*
 * Copyright 2012, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ssize_t apol_getline(char **lineptr, size_t *n, FILE *stream)
{
#ifdef __ANDROID__

    char *ptr;
    size_t len;

    if (lineptr == NULL || n == NULL) {
        errno = EINVAL;
        return -1;
    }

    ptr = fgetln(stream, n);
    if (ptr == NULL) {
        return -1;
    }

    /* Free the original ptr */
    if (*lineptr != NULL) free(*lineptr);

    /* Add one more space for '\0' */
    len = n[0] + 1;

    /* Update the length */
    n[0] = len;

    /* Allocate a new buffer */
    *lineptr = malloc(len);
    if (*lineptr == NULL) {
        errno = ENOMEM;
        return -1;
    }

    /* Copy over the string */
    memcpy(*lineptr, ptr, len-1);

    /* Write the NULL character */
    (*lineptr)[len-1] = '\0';

    /* Return the length of the new buffer */
    return (ssize_t)len;

#else /* __ANDROID__ */

    return getdelim(lineptr, n, '\n', stream);

#endif /* __ANDROID__ */
}
