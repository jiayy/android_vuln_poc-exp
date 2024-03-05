/**
 * @file
 *
 * This file is a copy of queue.h from NSA's CVS repository.  It has
 * been modified to follow the setools naming conventions.
 *
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil>
 *
 * A double-ended queue is a singly linked list of
 * elements of arbitrary type that may be accessed
 * at either end.
 */

#ifndef APOL_QUEUE_H
#define APOL_QUEUE_H

typedef struct apol_queue_node
{
	void *element;
	struct apol_queue_node *next;
} apol_queue_node_t;

typedef struct apol_queue
{
	apol_queue_node_t *head;
	apol_queue_node_t *tail;
} apol_queue_t;

/**
 * Allocate and return a new queue.  The caller is responsible for
 * calling apol_queue_destroy() upon the return value.
 *
 * @return A newly allocated queue, or NULL upon error.
 */
apol_queue_t *apol_queue_create(void);

/**
 * Adds an element to the end of a queue.
 *
 * @param q Queue to modify.
 * @param element Element to append to the end.
 *
 * @return 0 on success, < 0 on error.
 */
int apol_queue_insert(apol_queue_t * q, void *element);

/**
 * Adds an element to the beginning of a queue.
 *
 * @param q Queue to modify.
 * @param element Element to prepend to the beginning.
 *
 * @return 0 on success, < 0 on error.
 */
int apol_queue_push(apol_queue_t * q, void *element);

/**
 * Remove the first element from a queue and return the data; the
 * queue is advanced afterwards.  If the queue was empty then return
 * NULL.
 *
 * @return First element of a queue, or NULL if nothing is there.
 */
void *apol_queue_remove(apol_queue_t * q);

/**
 * Return the data within the first element, but do not remove it from
 * the queue.  If the queue was empty then return NULL.
 *
 * @return First element of a queue, or NULL if nothing is there.
 */
void *apol_queue_head(apol_queue_t * q);

/**
 * Destroy the referenced queue, but <i>do not</i> attempt to free the
 * data stored within.  (The caller is responsible for doing that.)
 * Afterwards set the referenced variable to NULL.  If the variable is
 * NULL then do nothing.
 *
 * @param Reference to a queue to destroy.
 */
void apol_queue_destroy(apol_queue_t ** q);

#endif

/* FLASK */
