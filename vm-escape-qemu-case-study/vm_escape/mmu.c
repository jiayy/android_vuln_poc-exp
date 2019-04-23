#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <inttypes.h>

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)

int fd;

uint32_t page_offset(uint32_t addr)
{
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void *addr)
{
	uint64_t pme, gfn;
	size_t offset;
	offset = ((uintptr_t)addr >> 9) & ~7;
	lseek(fd, offset, SEEK_SET);
	read(fd, &pme, 8);
	if (!(pme & PFN_PRESENT))
		return -1;
	gfn = pme & PFN_PFN;
	return gfn;
}

uint64_t gva_to_gpa(void *addr)
{
	uint64_t gfn = gva_to_gfn(addr);
	assert(gfn != -1);
	return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}

int main()
{
	uint8_t *ptr;
	uint64_t ptr_mem;

	fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	ptr = malloc(256);
	strcpy(ptr, "Where am I?");
	printf("%s\n", ptr);
	ptr_mem = gva_to_gpa(ptr);
	printf("Your physical address is at 0x%"PRIx64"\n", ptr_mem);

	return 0;
}
