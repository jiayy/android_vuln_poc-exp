#pragma once

#define KMALLOC64_PAGE_CNT ((32 + 8) / 8)

#define PACKET_FENGSHUI_CNT (0x100)
#define PACKET_SPRAY_CNT (0x100)
#define PACKET_FREE_HOLE_STEP (0x20)

int pagealloc_pad(int count, int size);
