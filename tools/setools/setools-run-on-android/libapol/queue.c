/**
 * @file
 *
 * This file is a copy of queue.h from NSA's CVS repository.  It has
 * been modified to follow the setools naming conventions.
 *
 * Author : Stephen Smalley (NSA), <sds@epoch.ncsc.mil>
 *
 * Implementation of the double-ended queue type.
 */

#include <stdlib.h>
#include "queue.h"

apol_queue_t *apol_queue_create(void)
{
	apol_queue_t *q;

	q = (apol_queue_t *) malloc(sizeof(apol_queue_t));
	if (q == NULL)
		return NULL;

	q->head = q->tail = NULL;

	return q;
}

int apol_queue_insert(apol_queue_t * q, void *element)
{
	apol_queue_node_t *newnode;

	if (!q)
		return -1;

	newnode = (apol_queue_node_t *) malloc(sizeof(struct apol_queue_node));
	if (newnode == NULL)
		return -1;

	newnode->element = element;
	newnode->next = NULL;

	if (q->head == NULL) {
		q->head = q->tail = newnode;
	} else {
		q->tail->next = newnode;
		q->tail = newnode;
	}

	return 0;
}

int apol_queue_push(apol_queue_t * q, void *element)
{
	apol_queue_node_t *newnode;

	if (!q)
		return -1;

	newnode = (apol_queue_node_t *) malloc(sizeof(apol_queue_node_t));
	if (newnode == NULL)
		return -1;

	newnode->element = element;
	newnode->next = NULL;

	if (q->head == NULL) {
		q->head = q->tail = newnode;
	} else {
		newnode->next = q->head;
		q->head = newnode;
	}

	return 0;
}

void *apol_queue_remove(apol_queue_t * q)
{
	apol_queue_node_t *node;
	void *element;

	if (!q)
		return NULL;

	if (q->head == NULL)
		return NULL;

	node = q->head;
	q->head = q->head->next;
	if (q->head == NULL)
		q->tail = NULL;

	element = node->element;
	free(node);

	return element;
}

void *apol_queue_head(apol_queue_t * q)
{
	if (!q)
		return NULL;

	if (q->head == NULL)
		return NULL;

	return q->head->element;
}

void apol_queue_destroy(apol_queue_t ** q)
{
	apol_queue_node_t *p, *temp;

	if (!q || *q == NULL)
		return;

	p = (*q)->head;
	while (p != NULL) {
		temp = p;
		p = p->next;
		free(temp);
	}

	free(*q);
	*q = NULL;
}
