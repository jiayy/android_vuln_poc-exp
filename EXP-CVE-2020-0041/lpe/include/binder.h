/* Copyright 2008 The Android Open Source Project
 */

#ifndef _BINDER_H_
#define _BINDER_H_

#include <sys/ioctl.h>
#include <stdbool.h>
#include <stdint.h>
#include "uapi_binder.h"

struct binder_state
{
    int fd;
    void *mapped;
    size_t mapsize;
};

struct binder_io
{
    char *data;            /* pointer to read/write from */
    binder_size_t *offs;   /* array of offsets */
    size_t data_avail;     /* bytes available in data buffer */
    size_t offs_avail;     /* entries available in offsets array */

    char *data0;           /* start of data buffer */
    binder_size_t *offs0;  /* start of offsets buffer */
    uint32_t flags;
    uint32_t unused;
};

struct binder_death {
    void (*func)(struct binder_state *bs, void *ptr);
    void *ptr;
};

/* the one magic handle */
#define BINDER_SERVICE_MANAGER  0U

#define SVC_MGR_NAME "android.os.IServiceManager"

enum {
    /* Must match definitions in IBinder.h and IServiceManager.h */
    PING_TRANSACTION  = B_PACK_CHARS('_','P','N','G'),
    SVC_MGR_GET_SERVICE = 1,
    SVC_MGR_CHECK_SERVICE,
    SVC_MGR_ADD_SERVICE,
    SVC_MGR_LIST_SERVICES,
    SVC_MGR_GET_RANDOM,
};

typedef int (*binder_handler)(struct binder_state *bs,
                              struct binder_transaction_data *txn,
                              struct binder_io *msg,
                              struct binder_io *reply);

struct binder_state *binder_open(const char* driver, size_t mapsize);
void binder_close(struct binder_state *bs);

/* initiate a blocking binder call
 * - returns zero on success
 */
int binder_call(struct binder_state *bs,
                struct binder_io *msg, struct binder_io *reply,
                uint32_t target, uint32_t code);

int binder_call2(struct binder_state *bs,
                struct binder_io *msg, struct binder_io *reply,
                uint32_t target, uint32_t code, char *buffer);

/* release any state associate with the binder_io
 * - call once any necessary data has been extracted from the
 *   binder_io after binder_call() returns
 * - can safely be called even if binder_call() fails
 */
void binder_done(struct binder_state *bs,
                 struct binder_io *msg, struct binder_io *reply);

/* manipulate strong references */
void binder_acquire(struct binder_state *bs, uint32_t target);
void binder_release(struct binder_state *bs, uint32_t target);

void binder_link_to_death(struct binder_state *bs, uint32_t target, struct binder_death *death);

void binder_loop(struct binder_state *bs, binder_handler func);

int binder_become_context_manager(struct binder_state *bs);

/* allocate a binder_io, providing a stack-allocated working
 * buffer, size of the working buffer, and how many object
 * offset entries to reserve from the buffer
 */
void bio_init(struct binder_io *bio, void *data,
           size_t maxdata, size_t maxobjects);

void bio_put_obj(struct binder_io *bio, void *ptr);
void bio_put_ref(struct binder_io *bio, uint32_t handle);
void bio_put_fd(struct binder_io *bio, int fd);
void *bio_put_ptr(struct binder_io *bio, void *buffer, uint32_t size, uint32_t *off);
void bio_put_fd_array(struct binder_io *bio, uint64_t parent, uint64_t parent_offset, int num_fds);
void bio_put_uint32(struct binder_io *bio, uint32_t n);
void bio_put_string16(struct binder_io *bio, const uint16_t *str);
void bio_put_string16_x(struct binder_io *bio, const char *_str);

uint32_t bio_get_uint32(struct binder_io *bio);
uint16_t *bio_get_string16(struct binder_io *bio, size_t *sz);
uint32_t bio_get_ref(struct binder_io *bio);
void *bio_alloc(struct binder_io *bio, size_t size);

int binder_write(struct binder_state *bs, void *data, size_t len);
int binder_read(int fd, void *buffer, size_t size);
int binder_transaction(struct binder_state *bs, bool one_way, uint32_t handle, void *opaque, size_t opaque_size, void *offsets, size_t offsets_size);

void binder_free_buffer(struct binder_state *bs, binder_uintptr_t buffer_to_free);
void binder_free_buffers(struct binder_state *bs, binder_uintptr_t buffer_to_free);



#endif
