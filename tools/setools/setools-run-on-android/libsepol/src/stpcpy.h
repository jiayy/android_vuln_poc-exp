/* Replacement for stpcpy(3) which is absent in android-16. */

#ifndef __STPCPY_H__
#define __STPCPY_H__

char *sepol_stpcpy(char *dst, const char *src);

#endif /* __STPCPY_H__ */
