#ifndef ENDPOINT_H_
# define ENDPOINT_H_
#include <setjmp.h>

struct endpoint_handle {
	struct endpoint_info *next;
	uint8_t *name;
	struct binder_state *bs;
	void *stack;
	pid_t pid;
	pthread_barrier_t barrier;
	int status;
	uint64_t client_handle;
	uint64_t reserved_buffer;
	jmp_buf env;
};



typedef enum {
	GET_VMA_START = 0,
	EXCHANGE_HANDLES,
	ADD_PENDING_NODE,
	TERMINATE_PENDING_NODE,
	RESERVE_BUFFER,
	FREE_RESERVED_BUFFER,
	TRIGGER_DECREF,
} endpoint_cmd_t;


bool bootstrap_endpoint(const char *endpoint_name);
bool terminate_endpoint(const char *endpoint_name);
struct endpoint_handle *get_endpoints();



#endif /*! ENDPOINT_H_ */
