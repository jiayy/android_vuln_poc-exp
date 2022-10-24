#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>

ssize_t log_info(const char *format, ...)
{
	va_list args;
	ssize_t len = 0;
	uint8_t buf[0x1000];
	memset(buf, 0, 0x1000);
	va_start(args, format);
	len = vsnprintf(buf, INT_MAX, format, args);
	va_end(args);

	if (len > 0)
		write(1, buf, len);
	return len;
}

ssize_t log_err(const char *format, ...)
{
	va_list args;
	ssize_t len = 0;
	uint8_t buf[0x1000];
	memset(buf, 0, 0x1000);
	va_start(args, format);
	len = vsnprintf(buf, INT_MAX, format, args);
	va_end(args);

	if (len > 0)
		write(2, buf, len);
	return len;
}




