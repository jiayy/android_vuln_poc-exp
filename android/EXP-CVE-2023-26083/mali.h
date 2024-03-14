#ifndef _H_MALI_H
#define _H_MALI_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <linux/types.h>
#include <sys/epoll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <assert.h>
#include <sched.h>
#include <sys/resource.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <android/log.h>
#include <sys/klog.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/system_properties.h>

#include "mali_base_common_kernel.h"
typedef __u32 base_mem_alloc_flags;

#define KBASE_API_VERSION(major, minor) ((((major) & 0xFFF) << 20)  |   \
                                         (((minor) & 0xFFF) << 8) |     \
                                         ((0 & 0xFF) << 0))

#define KBASE_API_MIN(api_version) ((api_version >> 8) & 0xFFF)
#define KBASE_API_MAJ(api_version) ((api_version >> 20) & 0xFFF)

#define KBASE_IOCTL_TYPE 0x80

struct kbase_ioctl_version_check {
        __u16 major;
        __u16 minor;
};

#define KBASE_IOCTL_VERSION_CHECK                                       \
        _IOWR(KBASE_IOCTL_TYPE, 52, struct kbase_ioctl_version_check)


struct kbase_ioctl_set_flags {
        __u32 create_flags;
};

#define KBASE_IOCTL_SET_FLAGS                                   \
        _IOW(KBASE_IOCTL_TYPE, 1, struct kbase_ioctl_set_flags)

struct kbase_ioctl_cs_queue_register {
        __u64 buffer_gpu_addr;
        __u32 buffer_size;
        __u8 priority;
        __u8 padding[3];
};

#define KBASE_IOCTL_CS_QUEUE_REGISTER                                   \
        _IOW(KBASE_IOCTL_TYPE, 36, struct kbase_ioctl_cs_queue_register)

union kbase_ioctl_mem_alloc {
        struct {
                __u64 va_pages;
                __u64 commit_pages;
                __u64 extension;
                __u64 flags;
        } in;
        struct {
                __u64 flags;
                __u64 gpu_va;
        } out;
};

#define KBASE_IOCTL_MEM_ALLOC                                   \
        _IOWR(KBASE_IOCTL_TYPE, 5, union kbase_ioctl_mem_alloc)

#endif /* _H_MALI_H */

union kbase_ioctl_cs_queue_bind {
        struct {
                __u64 buffer_gpu_addr;
                __u8 group_handle;
                __u8 csi_index;
                __u8 padding[6];
        } in;
        struct {
                __u64 mmap_handle;
        } out;
};

#define KBASE_IOCTL_CS_QUEUE_BIND                                       \
        _IOWR(KBASE_IOCTL_TYPE, 39, union kbase_ioctl_cs_queue_bind)

union kbase_ioctl_cs_queue_group_create {
        struct {
                __u64 tiler_mask;
                __u64 fragment_mask;
                __u64 compute_mask;
                __u8 cs_min;
                __u8 priority;
                __u8 tiler_max;
                __u8 fragment_max;
                __u8 compute_max;
                __u8 csi_handlers;
                __u8 padding[2];
                /**
                 * @in.reserved: Reserved
                 */
                __u64 reserved;
        } in;
        struct {
                __u8 group_handle;
                __u8 padding[3];
                __u32 group_uid;
        } out;
};

#define KBASE_IOCTL_CS_QUEUE_GROUP_CREATE                               \
        _IOWR(KBASE_IOCTL_TYPE, 58, union kbase_ioctl_cs_queue_group_create)



struct kbase_ioctl_cs_cpu_queue_info {
        __u64 buffer;
        __u64 size;
};

#define KBASE_IOCTL_CS_CPU_QUEUE_DUMP                                   \
        _IOW(KBASE_IOCTL_TYPE, 53, struct kbase_ioctl_cs_cpu_queue_info)

typedef __u8 base_kcpu_queue_id;
struct kbase_ioctl_kcpu_queue_new {
        base_kcpu_queue_id id;
        __u8 padding[7];
};
#define KBASE_IOCTL_KCPU_QUEUE_CREATE                                   \
        _IOR(KBASE_IOCTL_TYPE, 45, struct kbase_ioctl_kcpu_queue_new)


/* Enable KBase tracepoints for CSF builds */
#define BASE_TLSTREAM_ENABLE_CSF_TRACEPOINTS (1 << 2)

struct kbase_ioctl_tlstream_acquire {
        __u32 flags;
};

#define KBASE_IOCTL_TLSTREAM_ACQUIRE                                    \
        _IOW(KBASE_IOCTL_TYPE, 18, struct kbase_ioctl_tlstream_acquire)

struct kbase_pixel_gpu_slc_liveness_mark {
        __u32 type : 1;
        __u32 index : 31;
};
struct kbase_ioctl_buffer_liveness_update {
        __u64 live_ranges_address;
        __u64 live_ranges_count;
        __u64 buffer_va_address;
        __u64 buffer_sizes_address;
        __u64 buffer_count;
};

#define KBASE_IOCTL_BUFFER_LIVENESS_UPDATE                              \
        _IOW(KBASE_IOCTL_TYPE, 67, struct kbase_ioctl_buffer_liveness_update)

typedef __u8 base_kcpu_queue_id;

struct kbase_ioctl_kcpu_queue_delete {
        base_kcpu_queue_id id;
        __u8 padding[7];
};

#define KBASE_IOCTL_KCPU_QUEUE_DELETE                                   \
        _IOW(KBASE_IOCTL_TYPE, 46, struct kbase_ioctl_kcpu_queue_delete)

struct kbase_ioctl_get_context_id {
        __u32 id;
};

#define KBASE_IOCTL_GET_CONTEXT_ID _IOR(KBASE_IOCTL_TYPE, 17, struct kbase_ioctl_get_context_id)
