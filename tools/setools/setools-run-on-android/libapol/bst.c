/**
 *  @file
 *  Contains the implementation of a generic binary search tree.  The
 *  tree is implemented as a red-black tree, as inspired by Julienne
 *  Walker (http://eternallyconfuzzled.com/tuts/redblack.html).
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006-2007 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <apol/bst.h>
#include <apol/vector.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "vector-internal.h"

typedef struct bst_node
{
	void *elem;
	int is_red;
	struct bst_node *child[2];
} bst_node_t;

/**
 *  Generic binary search tree structure.  Stores elements as void*.
 */
struct apol_bst
{
	/** Comparison function for nodes. */
	apol_bst_comp_func *cmp;
	/** Destroy function for the nodes, or NULL to not free each node. */
	apol_bst_free_func *fr;
	/** The number of elements currently stored in the bst. */
	size_t size;
	/** Pointer to top of the tree. */
	bst_node_t *head;
};

apol_bst_t *apol_bst_create(apol_bst_comp_func * cmp, apol_bst_free_func * fr)
{
	apol_bst_t *b = NULL;
	if ((b = calloc(1, sizeof(*b))) == NULL) {
		return NULL;
	}
	b->cmp = cmp;
	b->fr = fr;
	return b;
}

/**
 * Free the data stored within a bst node, recurse through the node's
 * children, and then the node itself.
 *
 * @param node Node to free.  If NULL then do stop recursing.
 * @param fr Callback to free a node's data.  If NULL then do not free
 * the data.
 */
static void bst_node_free(bst_node_t * node, apol_bst_free_func * fr)
{
	if (node != NULL) {
		if (fr != NULL) {
			fr(node->elem);
		}
		bst_node_free(node->child[0], fr);
		bst_node_free(node->child[1], fr);
		free(node);
	}
}

void apol_bst_destroy(apol_bst_t ** b)
{
	if (!b || !(*b))
		return;
	bst_node_free((*b)->head, (*b)->fr);
	(*b)->head = NULL;
	free(*b);
	*b = NULL;
}

/**
 * Given a BST node, traverse the node infix, appending the node's
 * element to vector v.
 *
 * @param node BST node to recurse.
 * @param v Vector to which append.
 *
 * @return 0 on success, < 0 on error.
 */
static int bst_node_to_vector(bst_node_t * node, apol_vector_t * v)
{
	int retval;
	if (node == NULL) {
		return 0;
	}
	if ((retval = bst_node_to_vector(node->child[0], v)) < 0) {
		return retval;
	}
	if ((retval = apol_vector_append(v, node->elem)) < 0) {
		return retval;
	}
	return bst_node_to_vector(node->child[1], v);
}

apol_vector_t *apol_bst_get_vector(apol_bst_t * b, int change_owner)
{
	apol_vector_t *v = NULL;
	if (!b) {
		errno = EINVAL;
		return NULL;
	}
	if ((v = apol_vector_create_with_capacity(b->size, NULL)) == NULL) {
		return NULL;
	}
	if (bst_node_to_vector(b->head, v) < 0) {
		int error = errno;
		apol_vector_destroy(&v);
		errno = error;
		return NULL;
	}
	if (change_owner) {
		vector_set_free_func(v, b->fr);
		b->fr = NULL;
	}
	return v;
}

size_t apol_bst_get_size(const apol_bst_t * b)
{
	if (!b) {
		errno = EINVAL;
		return 0;
	} else {
		return b->size;
	}
}

int apol_bst_get_element(const apol_bst_t * b, const void *elem, void *data, void **result)
{
	bst_node_t *node;
	int compval;
	if (!b || !result) {
		errno = EINVAL;
		return -1;
	}
	node = b->head;
	while (node != NULL) {
		if (b->cmp != NULL) {
			compval = b->cmp(node->elem, elem, data);
		} else {
			char *p1 = (char *)node->elem;
			char *p2 = (char *)elem;
			if (p1 < p2) {
				compval = -1;
			} else if (p1 > p2) {
				compval = 1;
			} else {
				compval = 0;
			}
		}
		if (compval == 0) {
			*result = node->elem;
			return 0;
		} else if (compval > 0) {
			node = node->child[0];
		} else {
			node = node->child[1];
		}
	}
	return -1;
}

/**
 * Allocate and return a new BST node, with data set to elem and color
 * to red.  Also increment the tree's size.
 *
 * @param b BST size to increment.
 * @param elem Value for the node.
 *
 * @return Allocated BST node, which the caller must insert, or NULL
 * on error.
 */
static bst_node_t *bst_node_make(apol_bst_t * b, void *elem)
{
	bst_node_t *new_node;
	if ((new_node = calloc(1, sizeof(*new_node))) == NULL) {
		return NULL;
	}
	new_node->elem = elem;
	new_node->is_red = 1;
	b->size++;
	return new_node;
}

/**
 * Determines if a node is red or not.
 *
 * @param node Node to check.  If NULL then treat the node as black.
 *
 * @return 0 if the node is black, 1 if red.
 */
static int bst_node_is_red(bst_node_t * node)
{
	return node != NULL && node->is_red;
}

static bst_node_t *bst_rotate_single(bst_node_t * root, int dir)
{
	bst_node_t *save = root->child[!dir];
	root->child[!dir] = save->child[dir];
	save->child[dir] = root;
	root->is_red = 1;
	save->is_red = 0;
	return save;
}

static bst_node_t *bst_rotate_double(bst_node_t * root, int dir)
{
	root->child[!dir] = bst_rotate_single(root->child[!dir], !dir);
	return bst_rotate_single(root, dir);
}

static bst_node_t *bst_insert_recursive(apol_bst_t * b, bst_node_t * root, void **elem, void *data, apol_bst_free_func * fr,
					int *not_uniq)
{
	int compval, dir;
	if (root == NULL) {
		if ((root = bst_node_make(b, *elem)) == NULL) {
			*not_uniq = -1;
			return NULL;
		}
		*not_uniq = 0;
	} else {
		if (b->cmp != NULL) {
			compval = b->cmp(root->elem, *elem, data);
		} else {
			char *p1 = (char *)root->elem;
			char *p2 = (char *)(*elem);
			if (p1 < p2) {
				compval = -1;
			} else if (p1 > p2) {
				compval = 1;
			} else {
				compval = 0;
			}
		}
		if (compval == 0) {
			/* already exists */
			if (fr != NULL) {
				fr(*elem);
			}
			*elem = root->elem;
			*not_uniq = 1;
			return root;
		} else if (compval > 0) {
			dir = 0;
		} else {
			dir = 1;
		}
		root->child[dir] = bst_insert_recursive(b, root->child[dir], elem, data, fr, not_uniq);
		if (*not_uniq != 0) {
			return root;
		}

		/* rebalance tree */
		if (bst_node_is_red(root->child[dir])) {
			if (bst_node_is_red(root->child[!dir])) {
				/* recolor myself and children.  note
				 * that this can't be reached if a
				 * child is NULL */
				root->is_red = 1;
				root->child[0]->is_red = 0;
				root->child[1]->is_red = 0;
			} else {
				if (bst_node_is_red(root->child[dir]->child[dir])) {
					root = bst_rotate_single(root, !dir);
				} else if (bst_node_is_red(root->child[dir]->child[!dir])) {
					root = bst_rotate_double(root, !dir);
				}
			}
		}
	}
	return root;
}

int apol_bst_insert(apol_bst_t * b, void *elem, void *data)
{
	int retval = -1;
	if (!b || !elem) {
		errno = EINVAL;
		return -1;
	}
	b->head = bst_insert_recursive(b, b->head, &elem, data, NULL, &retval);
	if (retval >= 0) {
		b->head->is_red = 0;
	}
	return retval;
}

int apol_bst_insert_and_get(apol_bst_t * b, void **elem, void *data)
{
	int retval = -1;
	if (!b || !elem) {
		errno = EINVAL;
		return -1;
	}
	b->head = bst_insert_recursive(b, b->head, elem, data, b->fr, &retval);
	if (retval >= 0) {
		b->head->is_red = 0;
	}
	return retval;
}

static int bst_inorder_map(const bst_node_t * node, int (*fn) (void *, void *), void *data)
{
	int retval;
	if (node == NULL) {
		return 0;
	}
	if ((retval = bst_inorder_map(node->child[0], fn, data)) < 0) {
		return retval;
	}
	if ((retval = fn(node->elem, data)) < 0) {
		return retval;
	}
	return bst_inorder_map(node->child[1], fn, data);
}

int apol_bst_inorder_map(const apol_bst_t * b, int (*fn) (void *, void *), void *data)
{
	if (b == NULL || fn == NULL)
		return -1;
	return bst_inorder_map(b->head, fn, data);
}
