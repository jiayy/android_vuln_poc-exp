#include <string.h>

size_t regex_strlcpy(char *dst, const char *src, size_t dstsize)
{
	size_t src_len = strlen(src);

	strncpy(dst, src, dstsize - 1);
	if (src_len >= dstsize)
		dst[dstsize - 1] = '\0';

	return src_len;
}
