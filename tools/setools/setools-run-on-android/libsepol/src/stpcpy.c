#include <string.h>

char *sepol_stpcpy(char *dst, const char *src)
{
	strcpy(dst, src);

	return &dst[strlen(dst)];
}
