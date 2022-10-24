/* Copyright 2008 The Android Open Source Project
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "log.h"
#include "binder.h"
#include "uapi_binder.h"

#define MAX_BIO_SIZE (1 << 30)

#define TRACE 0

void bio_init_from_txn(struct binder_io *io, struct binder_transaction_data *txn);

#if TRACE
void hexdump(void *_data, size_t len)
{
    unsigned char *data = _data;
    size_t count;

    for (count = 0; count < len; count++) {
        if ((count & 15) == 0)
            flog_info(stderr,"%04zu:", count);
        flog_info(stderr,"\\x%02x", *data);
        // flog_info(stderr," %02x %c", *data,
                // (*data < 32) || (*data > 126) ? '.' : *data);
        data++;
        if ((count & 15) == 15)
            flog_info(stderr,"\n");
    }
    if ((count & 15) != 0)
        flog_info(stderr,"\n");
}

void binder_dump_txn(struct binder_transaction_data *txn)
{
    struct flat_binder_object *obj;
    binder_size_t *offs = (binder_size_t *)(uintptr_t)txn->data.ptr.offsets;
    size_t count = txn->offsets_size / sizeof(binder_size_t);

    flog_info(stderr,"  target %016"PRIx64"  cookie %016"PRIx64"  code %08x  flags %08x\n",
            (uint64_t)txn->target.ptr, (uint64_t)txn->cookie, txn->code, txn->flags);
    flog_info(stderr,"  pid %8d  uid %8d  data %"PRIu64"  offs %"PRIu64"\n",
            txn->sender_pid, txn->sender_euid, (uint64_t)txn->data_size, (uint64_t)txn->offsets_size);
    hexdump((void *)(uintptr_t)txn->data.ptr.buffer, txn->data_size);
    while (count--) {
        obj = (struct flat_binder_object *) (((char*)(uintptr_t)txn->data.ptr.buffer) + *offs++);
        flog_info(stderr,"  - type %08x  flags %08x  ptr %016"PRIx64"  cookie %016"PRIx64"\n",
                obj->hdr.type, obj->flags, (uint64_t)obj->binder, (uint64_t)obj->cookie);
    }
}

#define NAME(n) case n: return #n
const char *cmd_name(uint32_t cmd)
{
    switch(cmd) {
        NAME(BR_NOOP);
        NAME(BR_TRANSACTION_COMPLETE);
        NAME(BR_INCREFS);
        NAME(BR_ACQUIRE);
        NAME(BR_RELEASE);
        NAME(BR_DECREFS);
        NAME(BR_TRANSACTION);
        NAME(BR_REPLY);
        NAME(BR_FAILED_REPLY);
        NAME(BR_DEAD_REPLY);
        NAME(BR_DEAD_BINDER);
    default: return "???";
    }
}
#else
#define hexdump(a,b) do{} while (0)
#define binder_dump_txn(txn)  do{} while (0)
#endif

#define NAME(n) case n: return #n
const char *cmd_name(uint32_t cmd)
{
    switch(cmd) {
        NAME(BR_NOOP);
        NAME(BR_TRANSACTION_COMPLETE);
        NAME(BR_INCREFS);
        NAME(BR_ACQUIRE);
        NAME(BR_RELEASE);
        NAME(BR_DECREFS);
        NAME(BR_TRANSACTION);
        NAME(BR_REPLY);
        NAME(BR_FAILED_REPLY);
        NAME(BR_DEAD_REPLY);
        NAME(BR_DEAD_BINDER);
    default: return "???";
    }
}


#define BIO_F_SHARED    0x01  /* needs to be buffer freed */
#define BIO_F_OVERFLOW  0x02  /* ran out of space */
#define BIO_F_IOERROR   0x04
#define BIO_F_MALLOCED  0x08  /* needs to be free()'d */

struct binder_state *binder_open(const char* driver, size_t mapsize)
{
    struct binder_state *bs;
    struct binder_version vers;

    bs = malloc(sizeof(*bs));
    if (!bs) {
        errno = ENOMEM;
        return NULL;
    }

    bs->fd = open(driver, O_RDWR | O_CLOEXEC);
    if (bs->fd < 0) {
        log_info("binder: cannot open %s (%s)\n",
                driver, strerror(errno));
        goto fail_open;
    }

    if ((ioctl(bs->fd, BINDER_VERSION, &vers) == -1) ||
        (vers.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION)) {
        log_info(
                "binder: kernel driver version (%d) differs from user space version (%d)\n",
                vers.protocol_version, BINDER_CURRENT_PROTOCOL_VERSION);
        goto fail_open;
    }

    bs->mapsize = mapsize;
    bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);
    if (bs->mapped == MAP_FAILED) {
        log_info("binder: cannot map device (%s)\n",
                strerror(errno));
        goto fail_map;
    }

    return bs;

fail_map:
    close(bs->fd);
fail_open:
    free(bs);
    return NULL;
}

void binder_close(struct binder_state *bs)
{
    munmap(bs->mapped, bs->mapsize);
    close(bs->fd);
    free(bs);
}

int binder_become_context_manager(struct binder_state *bs)
{
    return ioctl(bs->fd, BINDER_SET_CONTEXT_MGR, 0);
}

int binder_write(struct binder_state *bs, void *data, size_t len)
{
    struct binder_write_read bwr;
    int res;

    bwr.write_size = len;
    bwr.write_consumed = 0;
    bwr.write_buffer = (uintptr_t) data;
    bwr.read_size = 0;
    bwr.read_consumed = 0;
    bwr.read_buffer = 0;
    res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
    if (res < 0) {
        log_info("binder_write: ioctl failed (%s)\n",
                strerror(errno));
    }
    return res;
}

/*
 * This is just sending 0x100 commands to free the buffer in a row,
 * saving us a few syscalls.
 */
void binder_free_buffers(struct binder_state *bs, binder_uintptr_t buffer_to_free)
{
    struct free_buf_data {
        uint32_t cmd_free;
        binder_uintptr_t buffer;
    } __attribute__((packed)) ;

    struct free_buf_data data[0x100];
    int i;

    for(i=0; i < 0x100; i++){
        data[i].cmd_free = BC_FREE_BUFFER;
        data[i].buffer = buffer_to_free;
    }

    binder_write(bs, &data[0], sizeof(data));
//    binder_write(bs, &data[0], sizeof(struct free_buf_data) * 0x10);

}


void binder_free_buffer(struct binder_state *bs,
                        binder_uintptr_t buffer_to_free)
{
    struct {
        uint32_t cmd_free;
        binder_uintptr_t buffer;
    } __attribute__((packed)) data;
    data.cmd_free = BC_FREE_BUFFER;
    data.buffer = buffer_to_free;
    binder_write(bs, &data, sizeof(data));
}

void binder_send_reply(struct binder_state *bs,
                       struct binder_io *reply,
                       binder_uintptr_t buffer_to_free,
                       int status)
{
    struct {
        uint32_t cmd_free;
        binder_uintptr_t buffer;
        uint32_t cmd_reply;
        struct binder_transaction_data txn;
    } __attribute__((packed)) data;

    data.cmd_free = BC_FREE_BUFFER;
    data.buffer = buffer_to_free;
    data.cmd_reply = BC_REPLY;
    data.txn.target.ptr = 0;
    data.txn.cookie = 0;
    data.txn.code = 0;
    if (status) {
        data.txn.flags = TF_STATUS_CODE;
        data.txn.data_size = sizeof(int);
        data.txn.offsets_size = 0;
        data.txn.data.ptr.buffer = (uintptr_t)&status;
        data.txn.data.ptr.offsets = 0;
    } else {
        data.txn.flags = 0;
        data.txn.data_size = reply->data - reply->data0;
        data.txn.offsets_size = ((char*) reply->offs) - ((char*) reply->offs0);
        data.txn.data.ptr.buffer = (uintptr_t)reply->data0;
        data.txn.data.ptr.offsets = (uintptr_t)reply->offs0;
    }
    binder_write(bs, &data, sizeof(data));
}

int binder_parse(struct binder_state *bs, struct binder_io *bio,
                 uintptr_t ptr, size_t size, binder_handler func)
{
    int r = 1;
    uintptr_t end = ptr + (uintptr_t) size;

    while (ptr < end) {
        uint32_t cmd = *(uint32_t *) ptr;
        ptr += sizeof(uint32_t);
#if TRACE
        log_info("%s:\n", cmd_name(cmd));
#endif
        switch(cmd) {
        case BR_NOOP:
            break;
        case BR_TRANSACTION_COMPLETE:
            break;
        case BR_INCREFS:
        case BR_ACQUIRE:
        case BR_RELEASE:
        case BR_DECREFS:
#if TRACE
            log_info("  %p, %p\n", (void *)ptr, (void *)(ptr + sizeof(void *)));
#endif
            ptr += sizeof(struct binder_ptr_cookie);
            break;
        case BR_TRANSACTION: {
            struct binder_transaction_data *txn = (struct binder_transaction_data *) ptr;
            if ((end - ptr) < sizeof(*txn)) {
                ALOGE("parse: txn too small!\n");
                return -1;
            }
            binder_dump_txn(txn);
            if (func) {
                unsigned rdata[256/4];
                struct binder_io msg;
                struct binder_io reply;
                int res;

                bio_init(&reply, rdata, sizeof(rdata), 4);
                bio_init_from_txn(&msg, txn);
                res = func(bs, txn, &msg, &reply);
                if (txn->flags & TF_ONE_WAY) {
                    binder_free_buffer(bs, txn->data.ptr.buffer);
                } else {
                    binder_send_reply(bs, &reply, txn->data.ptr.buffer, res);
                }
            }
            ptr += sizeof(*txn);
            break;
        }
        case BR_REPLY: {
            struct binder_transaction_data *txn = (struct binder_transaction_data *) ptr;
            if ((end - ptr) < sizeof(*txn)) {
                ALOGE("parse: reply too small!\n");
                return -1;
            }
            binder_dump_txn(txn);
            if (bio) {
                bio_init_from_txn(bio, txn);
                bio = 0;
            } else {
                /* todo FREE BUFFER */
            }
            ptr += sizeof(*txn);
            r = 0;
            break;
        }
        case BR_DEAD_BINDER: {
            struct binder_death *death = (struct binder_death *)(uintptr_t) *(binder_uintptr_t *)ptr;
            ptr += sizeof(binder_uintptr_t);
            death->func(bs, death->ptr);
            break;
        }
        case BR_FAILED_REPLY:
            r = -1;
            break;
        case BR_DEAD_REPLY:
            r = -1;
            break;
        default:
            ALOGE("parse: OOPS %d\n", cmd);
            return -1;
        }
    }

    return r;
}

void binder_acquire(struct binder_state *bs, uint32_t target)
{
    uint32_t cmd[2];
    cmd[0] = BC_ACQUIRE;
    cmd[1] = target;
    binder_write(bs, cmd, sizeof(cmd));
}

void binder_release(struct binder_state *bs, uint32_t target)
{
    uint32_t cmd[2];
    cmd[0] = BC_RELEASE;
    cmd[1] = target;
    binder_write(bs, cmd, sizeof(cmd));
}

void binder_link_to_death(struct binder_state *bs, uint32_t target, struct binder_death *death)
{
    struct {
        uint32_t cmd;
        struct binder_handle_cookie payload;
    } __attribute__((packed)) data;

    data.cmd = BC_REQUEST_DEATH_NOTIFICATION;
    data.payload.handle = target;
    data.payload.cookie = (uintptr_t) death;
    binder_write(bs, &data, sizeof(data));
}

int binder_call(struct binder_state *bs,
                struct binder_io *msg, struct binder_io *reply,
                uint32_t target, uint32_t code) {

    return binder_call2(bs, msg, reply, target, code, NULL);

}

int binder_call2(struct binder_state *bs,
                struct binder_io *msg, struct binder_io *reply,
                uint32_t target, uint32_t code, char *buffer)
{
    int res;
    struct binder_write_read bwr;
    struct {
        uint32_t cmd;
        struct binder_transaction_data txn;
    } __attribute__((packed)) writebuf;
    unsigned readbuf[32];

    if (msg->flags & BIO_F_OVERFLOW) {
        log_info("binder: txn buffer overflow\n");
        goto fail;
    }

    writebuf.cmd = BC_TRANSACTION;
    writebuf.txn.target.handle = target;
    writebuf.txn.code = code;
    writebuf.txn.flags = 0;
    writebuf.txn.data_size = msg->data - msg->data0;
    writebuf.txn.offsets_size = ((char*) msg->offs) - ((char*) msg->offs0);
    writebuf.txn.data.ptr.buffer = (uintptr_t)msg->data0;
    writebuf.txn.data.ptr.offsets = (uintptr_t)msg->offs0;

    bwr.write_size = sizeof(writebuf);
    bwr.write_consumed = 0;
    bwr.write_buffer = (uintptr_t) &writebuf;
    bwr.read_size = 0;
    bwr.read_consumed = 0;
    bwr.read_buffer = 0;

    // log_err("---------------- writebuf -------------\n");
    // hexdump(&writebuf, sizeof(writebuf));
    // log_err("----------------   Data   -------------\n");
    // hexdump(msg->data0, msg->data - msg->data0);
    // log_err("---------------- Offsets  -------------\n");
    // hexdump(msg->offs0, writebuf.txn.offsets_size);
    // log_err("IOCTL CODE: %x\n", BINDER_WRITE_READ);
    // log_err("DATA PTR: %p\n", msg->data0);
    // log_err("OFFS PTR: %p\n", msg->offs0);

    // log_err("---------------- bwr ------------------\n");
    // hexdump(&bwr, sizeof(bwr));

    for (;;) {
        uintptr_t thereadbuf = (buffer) ? (uintptr_t)buffer : (uintptr_t)readbuf;
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = thereadbuf;

        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);

        if (res < 0) {
            log_info("binder: ioctl failed (%s)\n", strerror(errno));
            goto fail;
        }

        res = binder_parse(bs, reply, (uintptr_t) thereadbuf, bwr.read_consumed, 0);
        if (res == 0) return 0;
        if (res < 0) goto fail;
    }

fail:
    memset(reply, 0, sizeof(*reply));
    reply->flags |= BIO_F_IOERROR;
    return -1;
}

int binder_call3(struct binder_state *bs,
                struct binder_io *msg, struct binder_io *reply,
                uint32_t target, uint32_t code, char *buffer)
{
    int res;
    struct binder_write_read bwr;
    struct {
        uint32_t cmd;
        struct binder_transaction_data txn;
    } __attribute__((packed)) writebuf;
    unsigned readbuf[32];

    if (msg->flags & BIO_F_OVERFLOW) {
        log_info("binder: txn buffer overflow\n");
        goto fail;
    }

    writebuf.cmd = BC_TRANSACTION;
    writebuf.txn.target.handle = target;
    writebuf.txn.code = code;
    writebuf.txn.flags = 0;
    writebuf.txn.data_size = msg->data - msg->data0;
    writebuf.txn.offsets_size = ((char*) msg->offs) - ((char*) msg->offs0);
    writebuf.txn.data.ptr.buffer = (uintptr_t)msg->data0;
    writebuf.txn.data.ptr.offsets = (uintptr_t)msg->offs0;

    bwr.write_size = sizeof(writebuf);
    bwr.write_consumed = 0;
    bwr.write_buffer = (uintptr_t) &writebuf;
    bwr.read_size = 0;
    bwr.read_consumed = 0;
    bwr.read_buffer = 0;

    // log_err("---------------- writebuf -------------\n");
    // hexdump(&writebuf, sizeof(writebuf));
    // log_err("----------------   Data   -------------\n");
    // hexdump(msg->data0, msg->data - msg->data0);
    // log_err("---------------- Offsets  -------------\n");
    // hexdump(msg->offs0, writebuf.txn.offsets_size);
    // log_err("IOCTL CODE: %x\n", BINDER_WRITE_READ);
    // log_err("DATA PTR: %p\n", msg->data0);
    // log_err("OFFS PTR: %p\n", msg->offs0);

    // log_err("---------------- bwr ------------------\n");
    // hexdump(&bwr, sizeof(bwr));

    for (;;) {
        uintptr_t thereadbuf = (buffer) ? (uintptr_t)buffer : (uintptr_t)readbuf;
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = thereadbuf;

        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);

        if (res < 0) {
            log_info("binder: ioctl failed (%s)\n", strerror(errno));
            goto fail;
        }

        res = binder_parse(bs, reply, (uintptr_t) thereadbuf, bwr.read_consumed, 0);
        if (res == 0) return 0;
        if (res < 0) goto fail;
    }

fail:
    memset(reply, 0, sizeof(*reply));
    reply->flags |= BIO_F_IOERROR;
    return -1;
}


void binder_loop(struct binder_state *bs, binder_handler func)
{
    int res;
    struct binder_write_read bwr;
    uint32_t readbuf[32];

    bwr.write_size = 0;
    bwr.write_consumed = 0;
    bwr.write_buffer = 0;

    readbuf[0] = BC_ENTER_LOOPER;
    binder_write(bs, readbuf, sizeof(uint32_t));

    for (;;) {
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = (uintptr_t) readbuf;

        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);

        if (res < 0) {
            ALOGE("binder_loop: ioctl failed (%s)\n", strerror(errno));
            break;
        }

        res = binder_parse(bs, 0, (uintptr_t) readbuf, bwr.read_consumed, func);
        if (res == 0) {
            ALOGE("binder_loop: unexpected reply?!\n");
            break;
        }
        if (res < 0) {
            ALOGE("binder_loop: io error %d %s\n", res, strerror(errno));
            break;
        }
    }
}

void binder_handle_transaction(struct binder_state *bs, binder_handler func)
{
    int res;
    struct binder_write_read bwr;
    uint32_t readbuf[32];

    bwr.write_size = 0;
    bwr.write_consumed = 0;
    bwr.write_buffer = 0;

    readbuf[0] = BC_ENTER_LOOPER;
    binder_write(bs, readbuf, sizeof(uint32_t));

	bwr.read_size = sizeof(readbuf);
	bwr.read_consumed = 0;
	bwr.read_buffer = (uintptr_t) readbuf;

	res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);

	if (res < 0) {
	    ALOGE("binder_loop: ioctl failed (%s)\n", strerror(errno));
	    return;
	}

	res = binder_parse(bs, 0, (uintptr_t) readbuf, bwr.read_consumed, func);
	if (res == 0) {
	    ALOGE("binder_loop: unexpected reply?!\n");
	    return;
	}
	if (res < 0) {
	    ALOGE("binder_loop: io error %d %s\n", res, strerror(errno));
	    return;
	}
}


void bio_init_from_txn(struct binder_io *bio, struct binder_transaction_data *txn)
{
    bio->data = bio->data0 = (char *)(intptr_t)txn->data.ptr.buffer;
    bio->offs = bio->offs0 = (binder_size_t *)(intptr_t)txn->data.ptr.offsets;
    bio->data_avail = txn->data_size;
    bio->offs_avail = txn->offsets_size / sizeof(size_t);
    bio->flags = BIO_F_SHARED;

}

void bio_init(struct binder_io *bio, void *data,
              size_t maxdata, size_t maxoffs)
{
    size_t n = maxoffs * sizeof(size_t);

    if (n > maxdata) {
        bio->flags = BIO_F_OVERFLOW;
        bio->data_avail = 0;
        bio->offs_avail = 0;
        return;
    }

    bio->data = bio->data0 = (char *) data + n;
    bio->offs = bio->offs0 = data;
    bio->data_avail = maxdata - n;
    bio->offs_avail = maxoffs;
    bio->flags = 0;
}

void *bio_alloc(struct binder_io *bio, size_t size)
{
    size = (size + 3) & (~3);
    if (size > bio->data_avail) {
        bio->flags |= BIO_F_OVERFLOW;
        return NULL;
    } else {
        void *ptr = bio->data;
        bio->data += size;
        bio->data_avail -= size;
        return ptr;
    }
}

void binder_done(struct binder_state *bs,
                 struct binder_io *msg,
                 struct binder_io *reply)
{
    struct {
        uint32_t cmd;
        uintptr_t buffer;
    } __attribute__((packed)) data;

    if (reply->flags & BIO_F_SHARED) {
        data.cmd = BC_FREE_BUFFER;
        data.buffer = (uintptr_t) reply->data0;
        binder_write(bs, &data, sizeof(data));
        reply->flags = 0;
    }
}

static struct flat_binder_object *bio_alloc_obj(struct binder_io *bio)
{
    struct flat_binder_object *obj;

    obj = bio_alloc(bio, sizeof(*obj));

    if (obj && bio->offs_avail) {
        bio->offs_avail--;
        *bio->offs++ = ((char*) obj) - ((char*) bio->data0);
        return obj;
    }

    bio->flags |= BIO_F_OVERFLOW;
    return NULL;
}

void bio_put_uint32(struct binder_io *bio, uint32_t n)
{
    uint32_t *ptr = bio_alloc(bio, sizeof(n));
    if (ptr)
        *ptr = n;
}

void bio_put_obj(struct binder_io *bio, void *ptr)
{
    struct flat_binder_object *obj;

    obj = bio_alloc_obj(bio);
    if (!obj)
        return;

    obj->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    obj->hdr.type = BINDER_TYPE_BINDER;
    obj->binder = (uintptr_t)ptr;
    obj->cookie = 0;
}

void bio_put_weak_obj(struct binder_io *bio, void *ptr)
{
    struct flat_binder_object *obj;

    obj = bio_alloc_obj(bio);
    if (!obj)
        return;

    obj->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    obj->hdr.type = BINDER_TYPE_WEAK_BINDER;
    obj->binder = (uintptr_t)ptr;
    obj->cookie = 0;


}


/* Add an offset to the list. */
void bio_add_offset(struct binder_io *bio, uint64_t offset)
{
	if (!bio->offs_avail)
		return;
	bio->offs_avail--;
	*bio->offs++ = offset;
}

/* Create a BINDER_TYPE_PTR object, which will contain arbitrary data. This can for example
 * be used to contains an array of file descriptors as used by the BINDER_TYPE_FDA, which
 * references the array within the BINDER_TYPE_PTR object.
 * The function returns a pointer to the allocated data, so that it can be set. If the "off"
 * pointer is submitted to the function, it will set it as well.
 */
void *bio_put_ptr(struct binder_io *bio, void *buffer, uint32_t size, uint32_t *off)
{
	struct binder_buffer_object *obj;
//	uint32_t _off = (bio->data - bio->data0);


	/* Allocate the object size + the size of the data we want it to contain. */
	obj = bio_alloc(bio, sizeof(*obj) + size);
	if (!obj)
		return NULL;

	if (obj && bio->offs_avail) {
		bio->offs_avail--;
		*bio->offs++ = ((char*) obj) - ((char*) bio->data0);
	}

	/* Compute the offset index. */
	obj->hdr.type = BINDER_TYPE_PTR;
	obj->flags |= BIO_F_OVERFLOW;
	obj->buffer = NULL;  /* The buffer address will need a fixup, this is dealt with the bio_fixup_ptr. */
	obj->length = size;
	obj->parent = 0;
	obj->parent_offset = 0;

	/* Copy the data to the binder buffer. */
	memcpy((obj + 1), buffer, size);

	if (off)
		*off = ((uint64_t)bio->offs - (uint64_t)bio->offs0) / sizeof(uint64_t) - 1;

	return NULL;
}

/* Fixup a ptr address of a BINDER_TYPE_PTR object given it's offset. */
void bio_fixup_ptr(struct binder_io *bio, void *base, uint32_t ptr_off)
{
	struct binder_buffer_object *obj;

	//TODO: Check the offset.
	
	/* Check it's actually a BINDER_TYPE_PTR */
	obj = (struct binder_buffer_object *)(bio->data0 + bio->offs0[ptr_off]);
	if (obj->hdr.type != BINDER_TYPE_PTR) {
		log_err("bio_fixup_ptr() -> Not a binder buffer object.\n");
		exit(1);
		return;
	}

	uint64_t buffer_off = bio->offs0[ptr_off] + sizeof(*obj);

	obj->buffer = base + buffer_off;
	log_info("obj->buffer: %p\n", obj->buffer);
}

/*
 * Create a BINDER_TYPE_FDA object, and give in parameters the parent offset in
 * the transaction, as well as the number of file descriptors, and the offset within
 * the parent BINDER_TYPE_PTR object.
 */
void bio_put_fd_array(struct binder_io *bio, uint64_t parent, uint64_t parent_offset, int num_fds)
{
	int i;
	struct binder_fd_array_object *fd_obj;

	/* Allocate the object containing the array. */
	fd_obj = bio_alloc(bio, sizeof(*fd_obj));
	if (!fd_obj)
		return;

	if (fd_obj && bio->offs_avail) {
		bio->offs_avail--;
		*bio->offs++ = ((char*) fd_obj) - ((char*) bio->data0);
	}

	fd_obj->hdr.type = BINDER_TYPE_FDA;
	fd_obj->num_fds = num_fds;
	fd_obj->parent = parent;
	fd_obj->parent_offset = parent_offset;
}

void bio_put_fd(struct binder_io *bio, int fd)
{
    struct binder_fd_object *obj;

    obj = bio_alloc_obj(bio);
    if (!obj)
        return;

    obj->hdr.type = BINDER_TYPE_FD;
    obj->fd = fd;
    obj->cookie = 0;
}

void bio_put_ref(struct binder_io *bio, uint32_t handle)
{
    struct flat_binder_object *obj;

    if (handle)
        obj = bio_alloc_obj(bio);
    else
        obj = bio_alloc(bio, sizeof(*obj));

    if (!obj)
        return;

    obj->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    obj->hdr.type = BINDER_TYPE_HANDLE;
    obj->handle = handle;
    obj->cookie = 0;
}




void bio_put_string16(struct binder_io *bio, const uint16_t *str)
{
    size_t len;
    uint16_t *ptr;

    if (!str) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    len = 0;
    while (str[len]) len++;

    if (len >= (MAX_BIO_SIZE / sizeof(uint16_t))) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    /* Note: The payload will carry 32bit size instead of size_t */
    bio_put_uint32(bio, (uint32_t) len);
    len = (len + 1) * sizeof(uint16_t);
    ptr = bio_alloc(bio, len);
    if (ptr)
        memcpy(ptr, str, len);
}

void bio_put_string16_x(struct binder_io *bio, const char *_str)
{
    unsigned char *str = (unsigned char*) _str;
    size_t len;
    uint16_t *ptr;

    if (!str) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    len = strlen(_str);

    if (len >= (MAX_BIO_SIZE / sizeof(uint16_t))) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    /* Note: The payload will carry 32bit size instead of size_t */
    bio_put_uint32(bio, len);
    ptr = bio_alloc(bio, (len + 1) * sizeof(uint16_t));
    if (!ptr)
        return;

    while (*str)
        *ptr++ = *str++;
    *ptr++ = 0;
}

static void *bio_get(struct binder_io *bio, size_t size)
{
    size = (size + 3) & (~3);

    if (bio->data_avail < size){
        bio->data_avail = 0;
        bio->flags |= BIO_F_OVERFLOW;
        return NULL;
    }  else {
        void *ptr = bio->data;
        bio->data += size;
        bio->data_avail -= size;
        return ptr;
    }
}

uint32_t bio_get_uint32(struct binder_io *bio)
{
    uint32_t *ptr = bio_get(bio, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

uint16_t *bio_get_string16(struct binder_io *bio, size_t *sz)
{
    size_t len;

    /* Note: The payload will carry 32bit size instead of size_t */
    len = (size_t) bio_get_uint32(bio);
    if (sz)
        *sz = len;
    return bio_get(bio, (len + 1) * sizeof(uint16_t));
}

static struct flat_binder_object *_bio_get_obj(struct binder_io *bio)
{
    size_t n;
    size_t off = bio->data - bio->data0;

    /* TODO: be smarter about this? */
    for (n = 0; n < bio->offs_avail; n++) {
        if (bio->offs[n] == off)
            return bio_get(bio, sizeof(struct flat_binder_object));
    }

    bio->data_avail = 0;
    bio->flags |= BIO_F_OVERFLOW;
    return NULL;
}

uint32_t bio_get_ref(struct binder_io *bio)
{
    struct flat_binder_object *obj;

    obj = _bio_get_obj(bio);
//    log_info("[*] Ref object at %p\n", obj);
    
    if (!obj)
        return 0;

    if (obj->hdr.type == BINDER_TYPE_HANDLE) {
        return obj->handle;
    }

    /* I added that for my tests, but I shouldn't be needed on Android. */
    if (obj->hdr.type == BINDER_TYPE_BINDER) {
	    return obj->handle;
    }

    return 0;
}

/* This is custom code added to the binder API, to aid in exploitation. */
int binder_read(int fd, void *buffer, size_t size)
{
	int res;
	struct binder_write_read bwr;

	bzero(&bwr, sizeof(bwr));

	bwr.read_buffer = buffer;
	bwr.read_size = size;

	res = ioctl(fd, BINDER_WRITE_READ, &bwr);

	if (res < 0) {
		log_err("binder_read() -> %s\n", strerror(errno));
		return res;
	}


	return bwr.read_consumed;
}

void *make_transaction(void *buffer, bool one_way, uint32_t handle, void *opaque, size_t opaque_size, void *offsets, size_t offsets_size)
{
	struct binder_transaction_data *tr;
	*(uint32_t *)buffer = BC_TRANSACTION;
	tr = (struct binder_transaction_data *)(buffer + sizeof(uint32_t));

	tr->target.handle = handle;
	//tr->flags = TF_ONE_WAY;
	tr->flags = one_way ? TF_ONE_WAY : 0;
	/* We do accept FDS. */
	tr->flags |= TF_ACCEPT_FDS;
	tr->data.ptr.buffer = opaque;
	tr->data_size = opaque_size;
	tr->data.ptr.offsets = offsets;
	tr->offsets_size = offsets_size;


	/* Return a pointer to the location for the next command. */
	return (void *)(tr + 1);
}

void *make_reply(void *buffer, bool one_way, uint32_t handle, void *opaque, size_t opaque_size, void *offsets, size_t offsets_size)
{
	struct binder_transaction_data *tr;
	*(uint32_t *)buffer = BC_REPLY;
	tr = (struct binder_transaction_data *)(buffer + sizeof(uint32_t));

	tr->target.handle = handle;
	//tr->flags = TF_ONE_WAY;
	tr->flags = one_way ? TF_ONE_WAY : 0;
	tr->data.ptr.buffer = opaque;
	tr->data_size = opaque_size;
	tr->data.ptr.offsets = offsets;
	tr->offsets_size = offsets_size;


	/* Return a pointer to the location for the next command. */
	return (void *)(tr + 1);
}


int binder_transaction(struct binder_state *bs, bool one_way, uint32_t handle, void *opaque, size_t opaque_size, void *offsets, size_t offsets_size)
{
	struct binder_transaction_data *tr;
	uint8_t buffer[sizeof(uint32_t) + sizeof(*tr)];
	uint32_t remaining = 0;
	uint32_t consumed = 0;

	make_transaction(buffer, one_way, handle, opaque, opaque_size, offsets, offsets_size);

	/* Sending the transaction. */
	int res = binder_write(bs, buffer, sizeof(buffer));
	if (res < 0)
		return res;
#if 0
	uint32_t r[32];
	int r2;
	r2 = binder_read(bs->fd, r, 32 * sizeof(uint32_t));
	/* TODO: Check results. */
	int i;
#endif


	return res;
}

int binder_reply(struct binder_state *bs, uint32_t handle, void *opaque, size_t opaque_size, void *offsets, size_t offsets_size)
{
	void *buffer;
	struct binder_transaction_data *tr;
	size_t size = sizeof(uint32_t) + sizeof(*tr);


	buffer = malloc(size);
	if (buffer == NULL) {
		log_err("[-] binder_transaction. Failed to allocate memory.\n");
		return -1;
	}

	bzero(buffer, size);


	make_transaction(buffer, false, handle, opaque, opaque_size, offsets, offsets_size);

	*(uint32_t *)(buffer) = BC_REPLY;

	/* Sending the transaction. */
	int res = binder_write(bs, buffer, size);
	/* TODO: Check result. */

	uint32_t r[32];
	int r2;
	r2 = binder_read(bs->fd, r, 32 * sizeof(uint32_t));
	/* TODO: Check results. */
	int i;

	free(buffer);

	return res;
}

uint32_t binder_read_next(struct binder_state *bs, void *data, uint32_t *remaining, uint32_t *consumed)
{
	int res;
	uint32_t cmd;
	void *ptr, *end;

//	log_info("remaining: %x\nconsumed: %x\n", *remaining, *consumed);

	if (!*remaining) {
		/* Read the first 8 bytes. */
//		log_info("before read\n");
		res = binder_read(bs->fd, data, 32 * sizeof(uint32_t));
//		log_info("after read: %x\n", res);
		if (res < 0) {
			log_err("binder_read_next: %s\n", strerror(errno));
			return (uint32_t)-1;
		}

		*remaining = res;
		*consumed = 0;
	}


	ptr = data;
	ptr += *consumed;
	end = ptr + *remaining;

	cmd = *(uint32_t *)ptr;

	*consumed += sizeof(uint32_t);
	*remaining -= sizeof(uint32_t);
	ptr += sizeof(uint32_t);

	//log_info("cmd: %s\n", cmd_name(cmd));
	switch (cmd) {
		case BR_NOOP:
			res = 0;
			break;

		case BR_RELEASE:
		case BR_DECREFS:
		case BR_ACQUIRE:
		case BR_INCREFS:
			res =2 * sizeof(uint64_t);
			*consumed += res;
			*remaining -= res;
			break;
		case BR_REPLY:
		case BR_TRANSACTION:
			res = sizeof(struct binder_transaction_data);
			*consumed += res;
			*remaining -= res;
			break;
		case BR_FAILED_REPLY:
		case BR_TRANSACTION_COMPLETE:
			res = 0;
			break;
		default:
			log_err("Unhandle command %s\n", cmd_name(cmd));
			exit(1);
			return (uint32_t)-1;

	}

	/* Update ptr and size */
	return cmd;
}

uint32_t binder_read_next_dbg(struct binder_state *bs, void *data, uint32_t *remaining, uint32_t *consumed)
{
	int res;
	uint32_t cmd;
	void *ptr, *end;

	log_info("remaining: %x\nconsumed: %x\n", *remaining, *consumed);

	if (!*remaining) {
		/* Read the first 8 bytes. */
//		log_info("before read\n");
		res = binder_read(bs->fd, data, 32 * sizeof(uint32_t));
//		log_info("after read: %x\n", res);
		if (res < 0) {
			log_err("binder_read_next: %s\n", strerror(errno));
			return (uint32_t)-1;
		}

		*remaining = res;
		*consumed = 0;
	}


	ptr = data;
	ptr += *consumed;
	end = ptr + *remaining;

	cmd = *(uint32_t *)ptr;

	*consumed += sizeof(uint32_t);
	*remaining -= sizeof(uint32_t);
	ptr += sizeof(uint32_t);

	log_info("cmd: %s\n", cmd_name(cmd));
	switch (cmd) {
		case BR_NOOP:
			res = 0;
			break;

		case BR_RELEASE:
		case BR_DECREFS:
		case BR_ACQUIRE:
		case BR_INCREFS:
			log_info("ptr: 0x%llx\n", *(uint64_t *)(ptr));
			log_info("cookie: 0x%llx\n", *(uint64_t *)(ptr + 0x8));
			res =2 * sizeof(uint64_t);
			*consumed += res;
			*remaining -= res;
			break;
		case BR_REPLY:
		case BR_TRANSACTION:
			res = sizeof(struct binder_transaction_data);
			*consumed += res;
			*remaining -= res;
			break;
		case BR_FAILED_REPLY:
		case BR_TRANSACTION_COMPLETE:
			res = 0;
			break;
		default:
			log_err("Unhandle command %s\n", cmd_name(cmd));
			exit(1);
			return (uint32_t)-1;

	}

	/* Update ptr and size */
	return cmd;
}

