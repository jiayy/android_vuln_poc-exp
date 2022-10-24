#ifndef PENDING_NODE_H_
#define PENDING_NODE_H_

typedef enum node_state
{
	NODE_NOT_READY,
	NODE_FINISHED,
   NODE_READY,
	NODE_LEAKED,
	NODE_FREE,
} node_state;

typedef struct pending_node
{
	node_state state;
	struct pending_node *next;
	struct binder_state *bs;
	pthread_barrier_t barrier; /* Barrier. */
   pthread_barrier_t ready; 
   pthread_barrier_t do_barrier;
   pthread_barrier_t done_barrier;
	uint64_t uaf_buffer; /* Address of binder buffer. */
	pthread_t uaf_node_th;
	uint64_t uaf_node;
	uint64_t leaked_data[2];

} pending_node;


void *pending_node_thread(void *args);
pthread_t add_pending_node(struct binder_state *from, uint64_t pending_node);
pthread_t pending_node_create(struct binder_state *bs, uint64_t node);

#endif /*! PENDING_NODE_H_ */
