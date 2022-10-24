#ifndef RING_HELPER_H
#define RING_HELPER_H
#include <liburing.h>
#include "err_state.h"

err_t init_timeout_sqe(struct io_uring *ring, struct timespec *ts)
{
    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
    IF_ERR_PTR(sqe) {
        perror("init_timeout_sqe:io_uring_get_sqe");
        return ERR;
    }
    sqe->opcode = IORING_OP_TIMEOUT;
    sqe->flags = IOSQE_IO_LINK;
    sqe->off = 4;
    sqe->addr = (uint64_t)ts;
    sqe->len = 1;
    sqe->user_data = 5;

    return SUCC;
}

err_t init_link_sqe(struct io_uring *ring, struct timespec *ts)
{
    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
    IF_ERR_PTR(sqe) {
        perror("init_link_sqe:io_uring_get_sqe");
        return ERR;
    }
    sqe->opcode = IORING_OP_LINK_TIMEOUT;
    sqe->addr = (uint64_t)ts;
    sqe->len = 1;
    sqe->user_data = 7;

    return SUCC;
}

err_t force_unblock_wait_cqe(struct io_uring *ring, uint32_t amount)
{
    struct io_uring_sqe* sqe = NULL;
    for (int i = 0; i < amount; i++) {
        sqe = io_uring_get_sqe(ring);
        IF_ERR_PTR(sqe) {
            perror("force_unblock_wait_cqe:io_uring_get_sqe");
            return ERR;
        }
    }
    IF_ERR(io_uring_submit(ring)) {
        perror("force_unblock_wait_cqe:io_uring_submit");
        return ERR;
    }
    return SUCC;
}

err_t init_ring(struct io_uring *ring)
{
    if (io_uring_queue_init(200, ring, 0) < 0) {
        perror("init_rings:io_uring_queue_init");
        return ERR;
    }
    return SUCC;
}

#endif // RING_HELPER_H