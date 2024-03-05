/**
 * @file
 * Implementation of the information flow analysis.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2007 Tresys Technology, LLC
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

#include "policy-query-internal.h"
#include "infoflow-analysis-internal.h"
#include "queue.h"
#include <apol/bst.h>
#include <apol/perm-map.h>

#include <assert.h>
#include <config.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <stdlib.h>

/*
 * Nodes in the graph represent either a type used in the source
 * of an allow rule or the target: these defines are used to
 * represent which.
 */
#define APOL_INFOFLOW_NODE_SOURCE 0x1
#define APOL_INFOFLOW_NODE_TARGET 0x2

/*
 * These defines are used to color nodes in the graph algorithms.
 */
#define APOL_INFOFLOW_COLOR_WHITE 0
#define APOL_INFOFLOW_COLOR_GREY  1
#define APOL_INFOFLOW_COLOR_BLACK 2
#define APOL_INFOFLOW_COLOR_RED   3

typedef struct apol_infoflow_node apol_infoflow_node_t;
typedef struct apol_infoflow_edge apol_infoflow_edge_t;

struct apol_infoflow_graph
{
	/** vector of apol_infoflow_node_t */
	apol_vector_t *nodes;
	/** vector of apol_infoflow_edge_t */
	apol_vector_t *edges;
	/** temporary BST of apol_infoflow_node_t used while building
         *  the graph */
	apol_bst_t *nodes_bst;

	unsigned int mode, direction;
	regex_t *regex;

	/** vector of apol_infoflow_node_t, used for random restarts
	 * for further transitive analysis */
	apol_vector_t *further_start;
	/** vector of apol_infoflow_node_t of targets, used for
	 * further transitive analysis */
	apol_vector_t *further_end;
	size_t current_start;
#ifdef HAVE_RAND_R
	unsigned int seed;
#endif
};

struct apol_infoflow_node
{
	const qpol_type_t *type;
	/** one of APOL_INFOFLOW_NODE_SOURCE or APOL_INFOFLOW_NODE_TARGET */
	int node_type;
	/** vector of apol_infoflow_edge_t, pointing into the graph */
	apol_vector_t *in_edges;
	/** vector of apol_infoflow_edge_t, pointing into the graph */
	apol_vector_t *out_edges;
	unsigned char color;
	apol_infoflow_node_t *parent;
	int distance;
};

struct apol_infoflow_edge
{
	/** vector of qpol_avrule_t, pointing into the policy */
	apol_vector_t *rules;
	/** pointer into a node within the graph */
	apol_infoflow_node_t *start_node;
	/** pointer into a node within the graph */
	apol_infoflow_node_t *end_node;
	int length;
};

/**
 * apol_infoflow_analysis_h encapsulates all of the paramaters of a
 * query.  It should always be allocated with
 * apol_infoflow_analysis_create() and deallocated with
 * apol_infoflow_analysis_destroy().  Limiting by ending_types,
 * obj_classes, intermed types, obj_class permissions is optional - if
 * the vector is empty then no limiting is done.
 *
 * All of the vectors except end_types should contain the items that
 * you want to not appear in the results.  end_types lists the types
 * that you do want to appear.
 */
struct apol_infoflow_analysis
{
	unsigned int mode, direction;
	char *type, *result;
	apol_vector_t *intermed, *class_perms;
	int min_weight;
};

/**
 * The results of running an infoflow, either direct or transitive, is
 * a path from start_type to end_type.  The path consists of a vector
 * of intermediate steps.
 */
struct apol_infoflow_result
{
	const qpol_type_t *start_type, *end_type;
	/** vector of apol_infoflow_step_t */
	apol_vector_t *steps;
	unsigned int direction;
	unsigned int length;
};

/**
 * Each result consists of multiple steps, representing the steps
 * taken from the original start to end types.  Along each step there
 * is a vector of rules.  For a direct infoflow analysis there will be
 * exactly one step, and that flow's start type is the same as the
 * original result's start_type.  Likewise the end_types will be the
 * same.
 */
struct apol_infoflow_step
{
	const qpol_type_t *start_type, *end_type;
	/** vector of qpol_avrule_t */
	apol_vector_t *rules;
	int weight;
};

/**
 * Deallocate all space associated with an apol_infoflow_step_t,
 * including the pointer itself.  Does nothing if the pointer is
 * already NULL.
 *
 * @param step Infoflow step to free.
 */
static void apol_infoflow_step_free(void *step)
{
	if (step != NULL) {
		apol_infoflow_step_t *s = (apol_infoflow_step_t *) step;
		apol_vector_destroy(&s->rules);
		free(s);
	}
}

/******************** random number routines ********************/

/**
 * Initialize the pseudo-random number generator to be used during
 * further transitive analysis.
 *
 * @param g Transitive infoflow graph.
 */
static void apol_infoflow_srand(apol_infoflow_graph_t * g)
{
#ifdef HAVE_RAND_R
	g->seed = (int)time(NULL);
#else
	srand((int)time(NULL));
#endif
}

/**
 * Return a pseudo-random integer between 0 and RAND_MAX, for use
 * during further transitive analysis.  If the system supports it,
 * this function will use rand_r() so that this library remains
 * reentrant and thread-safe.
 *
 * @param g Transitive infoflow graph.
 *
 * @return Integer between 0 and RAND_MAX.
 */
static int apol_infoflow_rand(apol_infoflow_graph_t * g)
{
#ifdef HAVE_RAND_R
	return rand_r(&g->seed);
#else
	return rand();
#endif
}

/******************** infoflow graph node routines ********************/

/**
 * Given a pointer to an apol_infoflow_node_t, free its space
 * including the pointer itself.  Does nothing if the pointer is
 * already NULL.
 *
 * @param data Node to free.
 */
static void apol_infoflow_node_free(void *data)
{
	apol_infoflow_node_t *node = (apol_infoflow_node_t *) data;
	if (node != NULL) {
		/* the edges themselves are owned by the graph, not by
		 * the node */
		apol_vector_destroy(&node->in_edges);
		apol_vector_destroy(&node->out_edges);
		free(node);
	}
}

struct apol_infoflow_node_key
{
	const qpol_type_t *type;
	int node_type;
};

/**
 * Given an infoflow node and a key, returns 0 if they are the same,
 * non-zero if not.
 *
 * @param a Existing node within the infoflow graph.
 * @param b <i>Unused.</i>
 * @param data Pointer to a struct infoflow_node_key.
 *
 * @return 0 if the key matches a, non-zero if not.
 */
static int apol_infoflow_node_compare(const void *a, const void *b __attribute__ ((unused)), void *data)
{
	apol_infoflow_node_t *node = (apol_infoflow_node_t *) a;
	struct apol_infoflow_node_key *key = (struct apol_infoflow_node_key *)data;
	if (node->type != key->type) {
		return (int)((char *)node->type - (char *)key->type);
	}
	return node->node_type - key->node_type;
}

/**
 * Attempt to allocate a new node, add it to the infoflow graph, and
 * return a pointer to it.  If there already exists a node with the
 * same type then reuse that node.
 *
 * @param p Policy handler, for reporting error.
 * @param g Infoflow to which add the node.
 * @param type Type for the new node.
 * @param node_type Node type, one of APOL_INFOFLOW_NODE_SOURCE or
 * APOL_INFOFLOW_NODE_TARGET.
 *
 * @return Pointer an allocated node within the infoflow graph, or
 * NULL upon error.
 */
static apol_infoflow_node_t *apol_infoflow_graph_create_node(const apol_policy_t * p,
							     apol_infoflow_graph_t * g, const qpol_type_t * type, int node_type)
{
	struct apol_infoflow_node_key key = { type, node_type };
	apol_infoflow_node_t *node = NULL;
	if (apol_bst_get_element(g->nodes_bst, NULL, &key, (void **)&node) == 0) {
		return node;
	}
	if ((node = calloc(1, sizeof(*node))) == NULL ||
	    (node->in_edges = apol_vector_create(NULL)) == NULL || (node->out_edges = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		apol_infoflow_node_free(node);
		return NULL;
	}
	node->type = type;
	node->node_type = node_type;
	if (apol_bst_insert(g->nodes_bst, node, &key) != 0) {
		ERR(p, "%s", strerror(errno));
		apol_infoflow_node_free(node);
		return NULL;
	}
	return node;
}

/**
 * Attempt to allocate a new node, add it to the infoflow graph, and
 * return a pointer to it.  If there already exists a node with the
 * same type then reuse that node.
 *
 * @param p Policy handler, for reporting error.
 * @param g Infoflow to which add the node.
 * @param type Type for the new node.  If this is an attribute then it
 * will be expanded into its component types.
 * @param types If non-NULL, a BST of qpol_type_t pointers.  Only
 * create and return nodes which are members of this tree.
 * @param node_type Node type, one of APOL_INFOFLOW_NODE_SOURCE or
 * APOL_INFOFLOW_NODE_TARGET.
 *
 * @return Vector of nodes (type apol_infoflow_node_t *) within the
 * infoflow graph, or NULL upon error.  The caller is responsible for
 * calling apol_vector_destroy() upon the return value.
 */
static apol_vector_t *apol_infoflow_graph_create_nodes(const apol_policy_t * p,
						       apol_infoflow_graph_t * g, const qpol_type_t * type, apol_bst_t * types,
						       int node_type)
{
	unsigned char isattr;
	apol_vector_t *v = NULL;
	apol_infoflow_node_t *node = NULL;
	if (qpol_type_get_isattr(p->p, type, &isattr) < 0) {
		return NULL;
	}
	if (isattr && g->mode != APOL_INFOFLOW_MODE_DIRECT) {
		qpol_iterator_t *iter = NULL;
		qpol_type_t *t;
		size_t len;
		if (qpol_type_get_type_iter(p->p, type, &iter) < 0 ||
		    qpol_iterator_get_size(iter, &len) < 0 || (v = apol_vector_create_with_capacity(len, NULL)) == NULL) {
			qpol_iterator_destroy(&iter);
			apol_vector_destroy(&v);
			return NULL;
		}
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			qpol_iterator_get_item(iter, (void **)&t);
			void *result;
			if (types != NULL && apol_bst_get_element(types, t, NULL, &result) < 0) {
				continue;
			}
			if ((node = apol_infoflow_graph_create_node(p, g, t, node_type)) == NULL || apol_vector_append(v, node) < 0) {
				qpol_iterator_destroy(&iter);
				apol_vector_destroy(&v);
				return NULL;
			}
		}
		qpol_iterator_destroy(&iter);
	} else {
		/* for a direct search, do not expand types; the
		 * algorithm will do that with
		 * apol_infoflow_graph_get_nodes_for_type() and
		 * apol_infoflow_analysis_direct_expand().  for
		 * transitive searches the \a types BST was checked in
		 * apol_infoflow_graph_check_types() if \a type is
		 * just a type.
		 */
		if ((v = apol_vector_create_with_capacity(1, NULL)) == NULL) {
			return NULL;
		}
		if ((node = apol_infoflow_graph_create_node(p, g, type, node_type)) == NULL || apol_vector_append(v, node) < 0) {
			apol_vector_destroy(&v);
			return NULL;
		}
	}
	return v;
}

/******************** infoflow graph edge routines ********************/

/**
 * Given a pointer to an apol_infoflow_edge_t, free its space
 * including the pointer itself.  Does nothing if the pointer is
 * already NULL.
 *
 * @param data Edge to free.
 */
static void apol_infoflow_edge_free(void *data)
{
	apol_infoflow_edge_t *edge = (apol_infoflow_edge_t *) data;
	if (edge != NULL) {
		apol_vector_destroy(&edge->rules);
		free(edge);
	}
}

struct apol_infoflow_edge_key
{
	apol_infoflow_node_t *start_node, *end_node;
};

/**
 * Given an infoflow edge and a key, returns 0 if they are the same,
 * non-zero if not.
 *
 * @param a Existing edge within the infoflow graph.
 * @param b <i>Unused.</i>
 * @param data Pointer to a struct infoflow_edge_key.
 *
 * @return 0 if the key matches a, non-zero if not.
 */
static int apol_infoflow_edge_compare(const void *a, const void *b __attribute__ ((unused)), void *data)
{
	apol_infoflow_edge_t *edge = (apol_infoflow_edge_t *) a;
	struct apol_infoflow_edge_key *key = (struct apol_infoflow_edge_key *)data;
	if (key->start_node != NULL && edge->start_node != key->start_node) {
		return (int)((char *)edge->start_node - (char *)key->start_node);
	}
	if (key->end_node != NULL && edge->end_node != key->end_node) {
		return (int)((char *)edge->end_node - (char *)key->end_node);
	}
	return 0;
}

/**
 * Attempt to allocate a new edge, add it to the infoflow graph, and
 * return a pointer to it.  If there already exists a edge from the
 * start node to the end node then reuse that edge.
 *
 * @param p Policy handler, for reporting errors.
 * @param g Infoflow graph to which add the edge.
 * @param start_node Starting node for the edge.
 * @param end_node Ending node for the edge.
 * @param len Length of edge (proportionally inverse of permission weight)
 *
 * @return Pointer an allocated node within the infoflow graph, or
 * NULL upon error.
 */
static apol_infoflow_edge_t *apol_infoflow_graph_create_edge(const apol_policy_t * p,
							     apol_infoflow_graph_t * g __attribute__ ((unused)),
							     apol_infoflow_node_t * start_node,
							     apol_infoflow_node_t * end_node, int len)
{
	struct apol_infoflow_edge_key key = { NULL, end_node };
	size_t i;
	apol_infoflow_edge_t *edge = NULL;
	if (apol_vector_get_index(start_node->out_edges, NULL, apol_infoflow_edge_compare, &key, &i) == 0) {
		edge = (apol_infoflow_edge_t *) apol_vector_get_element(start_node->out_edges, i);
		if (edge->length < len) {
			edge->length = len;
		}
		return edge;
	}
	if ((edge = calloc(1, sizeof(*edge))) == NULL || (edge->rules = apol_vector_create(NULL)) == NULL ||
	    apol_vector_append(g->edges, edge) < 0) {
		ERR(p, "%s", strerror(errno));
		apol_infoflow_edge_free(edge);
		return NULL;
	}
	edge->start_node = start_node;
	edge->end_node = end_node;
	edge->length = len;
	if (apol_vector_append(start_node->out_edges, edge) < 0 || apol_vector_append(end_node->in_edges, edge) < 0) {
		/* don't free the edge -- it is owned by the graph */
		ERR(p, "%s", strerror(errno));
		return NULL;
	}
	return edge;
}

/******************** infoflow graph creation routines ********************/

/**
 * Take an avrule within a policy and possibly add it to the infoflow
 * graph.  The rule's source and target type sets are expanded.  If
 * the rule is to be added, then add its end nodes as necessary, and
 * an edge connecting those nodes as necessary, and then add the rule
 * to the edge.
 *
 * @param p Policy containing rules.
 * @param g Information flow graph being created.
 * @param rule AV rule to use.
 * @param types BST of qpol_type_t pointers; while adding avrules to
 * the graph, only add those whose source and/or target is a member of
 * \a types, if \a types is non-NULL.
 * @param found_read Non-zero to indicate that this rule performs a
 * read operation.
 * @param read_len Length of the edge to create (proportionally
 * inverse of permission weight).
 * @param found_write Non-zero to indicate that this rule performs a
 * write operation.
 * @param write_len Length of the edge to create (proportionally
 * inverse of permission weight).
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_graph_connect_nodes(const apol_policy_t * p,
					     apol_infoflow_graph_t * g,
					     const qpol_avrule_t * rule,
					     apol_bst_t * types, int found_read, int read_len, int found_write, int write_len)
{
	const qpol_type_t *src_type, *tgt_type;
	apol_vector_t *src_nodes = NULL, *tgt_nodes = NULL;
	size_t i, j;
	apol_infoflow_node_t *src_node, *tgt_node;
	apol_infoflow_edge_t *edge;
	int retval = -1;

	if (qpol_avrule_get_source_type(p->p, rule, &src_type) < 0 || qpol_avrule_get_target_type(p->p, rule, &tgt_type) < 0) {
		goto cleanup;
	}

	if ((src_nodes = apol_infoflow_graph_create_nodes(p, g, src_type, types, APOL_INFOFLOW_NODE_SOURCE)) == NULL) {
		goto cleanup;
	}
	if ((tgt_nodes = apol_infoflow_graph_create_nodes(p, g, tgt_type, types, APOL_INFOFLOW_NODE_TARGET)) == NULL) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(src_nodes); i++) {
		src_node = apol_vector_get_element(src_nodes, i);
		for (j = 0; j < apol_vector_get_size(tgt_nodes); j++) {
			tgt_node = apol_vector_get_element(tgt_nodes, j);
			if (found_read) {
				if ((edge = apol_infoflow_graph_create_edge(p, g, tgt_node, src_node, read_len)) == NULL) {
					goto cleanup;
				}
				if (apol_vector_append(edge->rules, (void *)rule) < 0) {
					ERR(p, "%s", strerror(ENOMEM));
					goto cleanup;
				}
			}
			if (found_write) {
				if ((edge = apol_infoflow_graph_create_edge(p, g, src_node, tgt_node, write_len)) == NULL) {
					goto cleanup;
				}
				if (apol_vector_append(edge->rules, (void *)rule) < 0) {
					ERR(p, "%s", strerror(ENOMEM));
					goto cleanup;
				}
			}
		}
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&src_nodes);
	apol_vector_destroy(&tgt_nodes);
	return retval;
}

/**
 * Given a policy and a partially completed infoflow graph, create the
 * nodes and edges associated with a particular rule.
 *
 * @param p Policy from which to create the infoflow graph.
 * @param g Infoflow graph being created.
 * @param rule AV rule to add.
 * @param types BST of qpol_type_t pointers; while adding avrules to
 * the graph, only add those whose source and/or target is a member of
 * \a types, if \a types is non-NULL.
 * @param max_len Maximum permission length (i.e., inverse of
 * permission weight) to consider when deciding to add this rule or
 * not.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_graph_create_avrule(const apol_policy_t * p, apol_infoflow_graph_t * g, const qpol_avrule_t * rule,
					     apol_bst_t * types, int max_len)
{
	const qpol_class_t *obj_class;
	qpol_iterator_t *perm_iter = NULL;
	const char *obj_class_name;
	char *perm_name;
	int found_read = 0, found_write = 0, perm_error = 0;
	int read_len = INT_MAX, write_len = INT_MAX;
	int retval = -1;
	if (qpol_avrule_get_object_class(p->p, rule, &obj_class) < 0 ||
	    qpol_class_get_name(p->p, obj_class, &obj_class_name) < 0 || qpol_avrule_get_perm_iter(p->p, rule, &perm_iter) < 0) {
		goto cleanup;
	}

	/* find read or write flows for each object class/perm pair */
	for (; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
		int perm_map, perm_weight, len;

		if (qpol_iterator_get_item(perm_iter, (void **)&perm_name) < 0) {
			goto cleanup;
		}
		if (apol_policy_get_permmap(p, obj_class_name, perm_name, &perm_map, &perm_weight) < 0) {
			goto cleanup;
		}
		free(perm_name);
		if (perm_map == APOL_PERMMAP_UNMAPPED) {
			perm_error = 1;
			continue;
		}
		len = APOL_PERMMAP_MAX_WEIGHT - perm_weight + 1;
		if (len < APOL_PERMMAP_MIN_WEIGHT) {
			len = APOL_PERMMAP_MIN_WEIGHT;
		} else if (len > APOL_PERMMAP_MAX_WEIGHT) {
			len = APOL_PERMMAP_MAX_WEIGHT;
		}
		if (perm_map & APOL_PERMMAP_READ) {
			if (len < read_len && len <= max_len) {
				found_read = 1;
				read_len = len;
			}
		}
		if (perm_map & APOL_PERMMAP_WRITE) {
			if (len < write_len && len <= max_len) {
				found_write = 1;
				write_len = len;
			}
		}
	}

	/* if we have found any flows then connect them within the graph */
	if ((found_read || found_write) &&
	    apol_infoflow_graph_connect_nodes(p, g, rule, types, found_read, read_len, found_write, write_len) < 0) {
		goto cleanup;
	}
	if (perm_error) {
		WARN(p, "%s", "Not all of the permissions found had associated permission maps.");
	}

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&perm_iter);
	return retval;
}

/**
 * Given a vector of strings representing types, return a BST of
 * qpol_type_t pointers consisting of those types, those types'
 * attributes, and those types' aliases.
 *
 * @param p Policy within which to look up types,
 * @param v Vector of type strings.
 *
 * @return BST of qpol_type_t pointers, or NULL on error.  The caller
 * is responsible for calling apol_bst_destroy() upon the returned
 * value.
 */
static apol_bst_t *apol_infoflow_graph_create_required_types(const apol_policy_t * p, const apol_vector_t * v)
{
	apol_bst_t *types = NULL;
	apol_vector_t *expanded_types = NULL;
	size_t i;
	char *s;
	int retval = -1;
	if ((types = apol_bst_create(NULL, NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		s = (char *)apol_vector_get_element(v, i);
		expanded_types = apol_query_create_candidate_type_list(p, s, 0, 1, APOL_QUERY_SYMBOL_IS_BOTH);
		if (expanded_types == NULL) {
			goto cleanup;
		}
		for (size_t j = 0; j < apol_vector_get_size(expanded_types); j++) {
			qpol_type_t *t = (qpol_type_t *) apol_vector_get_element(expanded_types, j);
			if (apol_bst_insert(types, t, NULL) < 0) {
				ERR(p, "%s", strerror(errno));
				goto cleanup;
			}
		}
		apol_vector_destroy(&expanded_types);
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&expanded_types);
	if (retval != 0) {
		apol_bst_destroy(&types);
	}
	return types;
}

/**
 * Determine if an av rule matches a list of qpol_type_t pointers.
 * Both the source and target of the rule must be in the list.
 *
 * @param p Policy to which look up classes and permissions.
 * @param rule AV rule to check.
 * @param types BST of qpol_type_t, of which both the source and
 * target types must be members.  If NULL allow all types.
 *
 * @return 1 if rule matches, 0 if not, < 0 on error.
 */
static int apol_infoflow_graph_check_types(const apol_policy_t * p, const qpol_avrule_t * rule, const apol_bst_t * types)
{
	const qpol_type_t *source, *target;
	void *result;
	int retval = -1;
	if (types == NULL) {
		retval = 1;
		goto cleanup;
	}
	if (qpol_avrule_get_source_type(p->p, rule, &source) < 0 || qpol_avrule_get_target_type(p->p, rule, &target) < 0) {
		goto cleanup;
	}
	if (apol_bst_get_element(types, source, NULL, &result) < 0 || apol_bst_get_element(types, target, NULL, &result) < 0) {
		retval = 0;
		goto cleanup;
	}
	retval = 1;
      cleanup:
	return retval;
}

/**
 * Determine if an av rule matches a list of apol_obj_perm_t.  The
 * rule's class must match at least one item in the list, and at least
 * one of the rule's permissions must be on the list.
 *
 * @param p Policy to which look up classes and permissions.
 * @param rule AV rule to check.
 * @param class_perms Vector of apol_obj_perm_t, of which rule's class
 * and permissions must be a member.  If NULL or empty then allow all
 * classes and permissions.
 *
 * @return 1 if rule matches, 0 if not, < 0 on error.
 */
static int apol_infoflow_graph_check_class_perms(const apol_policy_t * p, const qpol_avrule_t * rule,
						 const apol_vector_t * class_perms)
{
	const qpol_class_t *obj_class;
	const char *obj_name;
	char *perm;
	qpol_iterator_t *iter = NULL;
	apol_obj_perm_t *obj_perm = NULL;
	apol_vector_t *obj_perm_v = NULL;
	size_t i;
	int retval = -1;

	if (class_perms == NULL || apol_vector_get_size(class_perms) == 0) {
		retval = 1;
		goto cleanup;
	}
	if (qpol_avrule_get_object_class(p->p, rule, &obj_class) < 0 || qpol_class_get_name(p->p, obj_class, &obj_name) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(class_perms); i++) {
		obj_perm = (apol_obj_perm_t *) apol_vector_get_element(class_perms, i);
		if (strcmp(apol_obj_perm_get_obj_name(obj_perm), obj_name) == 0) {
			obj_perm_v = apol_obj_perm_get_perm_vector(obj_perm);
			break;
		}
	}
	if (i >= apol_vector_get_size(class_perms)) {
		retval = 0;	       /* no matching class */
		goto cleanup;
	}
	if (qpol_avrule_get_perm_iter(p->p, rule, &iter) < 0) {
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&perm) < 0) {
			goto cleanup;
		}
		if (apol_vector_get_index(obj_perm_v, perm, apol_str_strcmp, NULL, &i) == 0) {
			free(perm);
			retval = 1;
			goto cleanup;
		}
		free(perm);
	}
	retval = 0;		       /* no matching perm */
      cleanup:
	qpol_iterator_destroy(&iter);
	return retval;
}

/**
 * Given a particular information flow analysis object, generate an
 * infoflow graph relative to a particular policy.  This graph is
 * customized for the particular analysis.
 *
 * @param p Policy from which to create the infoflow graph.
 * @param ia Parameters to tune the created graph.
 * @param g Reference to where to store the graph.  The caller is
 * responsible for calling apol_infoflow_graph_destroy() upon this.
 *
 * @return 0 if the graph was created, < 0 on error.  Upon error *g
 * will be set to NULL.
 */
static int apol_infoflow_graph_create(const apol_policy_t * p, const apol_infoflow_analysis_t * ia, apol_infoflow_graph_t ** g)
{
	apol_bst_t *types = NULL;
	qpol_iterator_t *iter = NULL;
	int max_len = APOL_PERMMAP_MAX_WEIGHT - ia->min_weight + 1;
	int compval, retval = -1;

	*g = NULL;
	if (p->pmap == NULL) {
		ERR(p, "%s", "A permission map must be loaded prior to building the infoflow graph.");
		goto cleanup;
	}

	INFO(p, "%s", "Generating information flow graph.");
	if (ia->mode == APOL_INFOFLOW_MODE_TRANS && ia->intermed != NULL &&
	    (types = apol_infoflow_graph_create_required_types(p, ia->intermed)) == NULL) {
		goto cleanup;
	}

	if ((*g = calloc(1, sizeof(**g))) == NULL ||
	    ((*g)->nodes_bst = apol_bst_create(apol_infoflow_node_compare, apol_infoflow_node_free)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	(*g)->mode = ia->mode;
	(*g)->direction = ia->direction;
	if (ia->result != NULL && ia->result[0] != '\0') {
		if (((*g)->regex = malloc(sizeof(regex_t))) == NULL || regcomp((*g)->regex, ia->result, REG_EXTENDED | REG_NOSUB)) {
			ERR(p, "%s", strerror(errno));
			goto cleanup;
		}
	}
	if (((*g)->edges = apol_vector_create(apol_infoflow_edge_free)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}

	if (qpol_policy_get_avrule_iter(p->p, QPOL_RULE_ALLOW, &iter) < 0) {
		goto cleanup;
	}

	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_avrule_t *rule;
		if (qpol_iterator_get_item(iter, (void **)&rule) < 0) {
			goto cleanup;
		}
		compval = apol_infoflow_graph_check_types(p, rule, types);
		if (compval < 0) {
			goto cleanup;
		} else if (compval == 0) {
			continue;
		}
		compval = apol_infoflow_graph_check_class_perms(p, rule, ia->class_perms);
		if (compval < 0) {
			goto cleanup;
		} else if (compval == 0) {
			continue;
		}
		if (apol_infoflow_graph_create_avrule(p, *g, rule, types, max_len) < 0) {
			goto cleanup;
		}
	}

	if (((*g)->nodes = apol_bst_get_vector((*g)->nodes_bst, 1)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	apol_bst_destroy(&(*g)->nodes_bst);
	retval = 0;
      cleanup:
	apol_bst_destroy(&types);
	qpol_iterator_destroy(&iter);
	if (retval < 0) {
		apol_infoflow_graph_destroy(g);
	}
	return retval;
}

void apol_infoflow_graph_destroy(apol_infoflow_graph_t ** g)
{
	if (g != NULL && *g != NULL) {
		apol_bst_destroy(&(*g)->nodes_bst);
		apol_vector_destroy(&(*g)->nodes);
		apol_vector_destroy(&(*g)->edges);
		apol_vector_destroy(&(*g)->further_start);
		apol_vector_destroy(&(*g)->further_end);
		apol_regex_destroy(&(*g)->regex);
		free(*g);
		*g = NULL;
	}
}

/*************** infoflow graph direct analysis routines ***************/

/**
 * Given a graph and a target type, append to vector v all nodes
 * (apol_infoflow_node_t) within the graph that use that type, one of
 * that type's aliases, or one of that type's attributes.  This will
 * also implicitly permutate across all of the type's object classes.
 *
 * @param p Error reporting handler.
 * @param g Information flow graph containing nodes.
 * @param type Target type name to find.
 * @param v Initialized vector to which append nodes.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_graph_get_nodes_for_type(const apol_policy_t * p, const apol_infoflow_graph_t * g, const char *type,
						  apol_vector_t * v)
{
	size_t i, j;
	apol_vector_t *cand_list = NULL;
	int retval = -1;
	if ((cand_list = apol_query_create_candidate_type_list(p, type, 0, 1, APOL_QUERY_SYMBOL_IS_BOTH)) == NULL) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(g->nodes); i++) {
		apol_infoflow_node_t *node;
		node = (apol_infoflow_node_t *) apol_vector_get_element(g->nodes, i);
		if (apol_vector_get_index(cand_list, node->type, NULL, NULL, &j) == 0 && apol_vector_append(v, node) < 0) {
			goto cleanup;
		}
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&cand_list);
	return retval;
}

/**
 * Return a usable infoflow result object.  If there already exists a
 * result object within vector v with the same start and ending type
 * then reuse that object.  Otherwise allocate and return a new
 * infoflow result with its start and end type fields set.
 *
 * @param p Policy handler, for reporting errors.
 * @param v Non-null vector of infoflow results.
 * @param start_type Starting type for returned infoflow result object.
 * @param end_type Starting type for returned infoflow result object.
 *
 * @return A usable infoflow result object, or NULL upon error.
 */
static apol_infoflow_result_t *apol_infoflow_direct_get_result(const apol_policy_t * p,
							       apol_vector_t * v, const qpol_type_t * start_type,
							       const qpol_type_t * end_type)
{
	size_t i;
	apol_infoflow_result_t *r;
	for (i = 0; i < apol_vector_get_size(v); i++) {
		r = (apol_infoflow_result_t *) apol_vector_get_element(v, i);
		if (r->start_type == start_type && r->end_type == end_type) {
			return r;
		}
	}
	if ((r = calloc(1, sizeof(*r))) == NULL || (r->steps = apol_vector_create(apol_infoflow_step_free)) == NULL
	    || apol_vector_append(v, r) < 0) {
		ERR(p, "%s", strerror(ENOMEM));
		infoflow_result_free(r);
		return NULL;
	}
	r->start_type = start_type;
	r->end_type = end_type;
	r->length = INT_MAX;
	return r;
}

/**
 * Append the rules on an edge to a direct infoflow result.
 *
 * @param p Policy containing rules.
 * @param edge Infoflow edge containing rules.
 * @param direction Direction of flow, one of APOL_INFOFLOW_IN, etc.
 * @param result Infoflow result to modify.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_direct_define(const apol_policy_t * p,
				       const apol_infoflow_edge_t * edge, unsigned int direction, apol_infoflow_result_t * result)
{
	apol_infoflow_step_t *step = NULL;
	if (apol_vector_get_size(result->steps) == 0) {
		if ((step = calloc(1, sizeof(*step))) == NULL ||
		    (step->rules = apol_vector_create(NULL)) == NULL || apol_vector_append(result->steps, step) < 0) {
			apol_infoflow_step_free(step);
			ERR(p, "%s", strerror(ENOMEM));
			return -1;
		}
		step->start_type = result->start_type;
		step->end_type = result->end_type;
		step->weight = 0;
	} else {
		step = (apol_infoflow_step_t *) apol_vector_get_element(result->steps, 0);
	}
	if (apol_vector_cat(step->rules, edge->rules) < 0) {
		ERR(p, "%s", strerror(ENOMEM));
		return -1;
	}
	result->direction |= direction;
	//TODO: check that edge->lenght can be safely unsigned
	if (edge->length < (int)result->length) {
		result->length = edge->length;
	}
	return 0;
}

/**
 * Given the regular expression compiled into the graph object and a
 * type, determine if that regex matches that type or any of the
 * type's aliases.
 *
 * @param p Policy containing type names.
 * @param g Graph object containing regex.
 * @param type Type to check against.
 *
 * @return 1 if comparison succeeds, 0 if not, < 0 on error.
 */
static int apol_infoflow_graph_compare(const apol_policy_t * p, apol_infoflow_graph_t * g, const qpol_type_t * type)
{
	const char *type_name;
	qpol_iterator_t *alias_iter = NULL;
	int compval = 0;
	if (g->regex == NULL) {
		return 1;
	}
	if (qpol_type_get_name(p->p, type, &type_name) < 0) {
		return -1;
	}
	if (regexec(g->regex, type_name, 0, NULL, 0) == 0) {
		return 1;
	}
	/* also check for matches against any of target's aliases */
	if (qpol_type_get_alias_iter(p->p, type, &alias_iter) < 0) {
		return -1;
	}
	for (; !qpol_iterator_end(alias_iter); qpol_iterator_next(alias_iter)) {
		char *iter_name;
		if (qpol_iterator_get_item(alias_iter, (void **)&iter_name) < 0) {
			compval = -1;
			break;
		}
		if (regexec(g->regex, iter_name, 0, NULL, 0) == 0) {
			compval = 1;
			break;
		}
	}
	qpol_iterator_destroy(&alias_iter);
	return compval;
}

/**
 * For each result object in vector working_results, append a
 * duplicate of it to vector results if (a) the infoflow analysis
 * object direction is not BOTH or (b) the result object's direction
 * is BOTH.  Regardless of success or error, it is safe to destroy
 * either vector without concern of double-free()ing things.
 *
 * @param p Policy handler, for reporting errors.
 * @param working_results Vector of infoflow results to check.
 * @param direction Direction of search.
 * @param results Vector to which append duplicated infoflow results.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_results_check_both(const apol_policy_t * p,
					    const apol_vector_t * working_results, unsigned int direction, apol_vector_t * results)
{
	size_t i;
	apol_infoflow_result_t *r, *new_r;
	for (i = 0; i < apol_vector_get_size(working_results); i++) {
		r = (apol_infoflow_result_t *) apol_vector_get_element(working_results, i);
		if (direction != APOL_INFOFLOW_BOTH || r->direction == APOL_INFOFLOW_BOTH) {
			if ((new_r = calloc(1, sizeof(*new_r))) == NULL) {
				ERR(p, "%s", strerror(ENOMEM));
				return -1;
			}
			memcpy(new_r, r, sizeof(*new_r));
			r->steps = NULL;
			if (apol_vector_append(results, new_r) < 0) {
				infoflow_result_free(new_r);
				ERR(p, "%s", strerror(ENOMEM));
				return -1;
			}
		}
	}
	return 0;
}

/**
 * Given a start node, an edge, and flow direction, add an infoflow
 * results to a vector.  If the node on the other end of the edge is
 * an attribute, first expand the attribute to its component types.
 * If a regular expression is compiled into the infoflow graph, apply
 * that regex match against candidate end node types prior to creating
 * result nodes.
 *
 * @param p Policy to analyze.
 * @param g Information flow graph to analyze.
 * @param start_node Starting node.
 * @param edge An edge from start_node.
 * @param flow_dir Direction of search, either APOL_INFOFLOW_IN or
 * APOL_INFOFLOW_OUT.
 * @param results Non-NULL vector to which append infoflow results.
 * The caller is responsible for calling apol_infoflow_results_free()
 * upon each element afterwards.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_analysis_direct_expand(const apol_policy_t * p,
						apol_infoflow_graph_t * g,
						apol_infoflow_node_t * start_node,
						apol_infoflow_edge_t * edge, unsigned int flow_dir, apol_vector_t * results)
{
	apol_infoflow_node_t *end_node;
	unsigned char isattr;
	qpol_iterator_t *iter = NULL;
	const qpol_type_t *type;
	apol_infoflow_result_t *r;
	int retval = -1, compval;

	if (edge->start_node == start_node) {
		end_node = edge->end_node;
	} else {
		end_node = edge->start_node;
	}
	if (qpol_type_get_isattr(p->p, end_node->type, &isattr) < 0) {
		goto cleanup;
	}
	if (isattr) {
		if (qpol_type_get_type_iter(p->p, end_node->type, &iter) < 0) {
			goto cleanup;
		}
		if (qpol_iterator_end(iter)) {
			retval = 0;
			goto cleanup;
		}
	}
	/* always do this loop once, either if end_node is an attribute or not */
	do {
		if (isattr) {
			if (qpol_iterator_get_item(iter, (void **)&type) < 0) {
				goto cleanup;
			}
			qpol_iterator_next(iter);
		} else {
			type = end_node->type;
		}
		compval = apol_infoflow_graph_compare(p, g, type);
		if (compval < 0) {
			goto cleanup;
		} else if (compval == 0) {
			continue;
		}
		if ((r = apol_infoflow_direct_get_result(p, results, start_node->type, type)) == NULL ||
		    apol_infoflow_direct_define(p, edge, flow_dir, r) < 0) {
			goto cleanup;
		}
	} while (isattr && !qpol_iterator_end(iter));

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
	return retval;
}

/**
 * Perform a direct information flow analysis upon the given infoflow
 * graph.
 *
 * @param p Policy to analyze.
 * @param g Information flow graph to analyze.
 * @param start_type Type from which to begin search.
 * @param results Non-NULL vector to which append infoflow results.
 * The caller is responsible for calling apol_infoflow_results_free()
 * upon each element afterwards.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_analysis_direct(const apol_policy_t * p,
					 apol_infoflow_graph_t * g, const char *start_type, apol_vector_t * results)
{
	apol_vector_t *nodes = NULL;
	size_t i, j;
	apol_infoflow_node_t *node;
	apol_infoflow_edge_t *edge;
	apol_vector_t *working_results = NULL;
	int retval = -1;

	if ((nodes = apol_vector_create(NULL)) == NULL || (working_results = apol_vector_create(infoflow_result_free)) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_infoflow_graph_get_nodes_for_type(p, g, start_type, nodes) < 0) {
		goto cleanup;
	}

	if (g->direction == APOL_INFOFLOW_IN || g->direction == APOL_INFOFLOW_EITHER || g->direction == APOL_INFOFLOW_BOTH) {
		for (i = 0; i < apol_vector_get_size(nodes); i++) {
			node = (apol_infoflow_node_t *) apol_vector_get_element(nodes, i);
			for (j = 0; j < apol_vector_get_size(node->in_edges); j++) {
				edge = (apol_infoflow_edge_t *) apol_vector_get_element(node->in_edges, j);
				if (apol_infoflow_analysis_direct_expand(p, g, node, edge, APOL_INFOFLOW_IN, working_results) < 0) {
					goto cleanup;
				}
			}
		}
	}
	if (g->direction == APOL_INFOFLOW_OUT || g->direction == APOL_INFOFLOW_EITHER || g->direction == APOL_INFOFLOW_BOTH) {
		for (i = 0; i < apol_vector_get_size(nodes); i++) {
			node = (apol_infoflow_node_t *) apol_vector_get_element(nodes, i);
			for (j = 0; j < apol_vector_get_size(node->out_edges); j++) {
				edge = (apol_infoflow_edge_t *) apol_vector_get_element(node->out_edges, j);
				if (apol_infoflow_analysis_direct_expand(p, g, node, edge, APOL_INFOFLOW_OUT, working_results) < 0) {
					goto cleanup;
				}
			}
		}
	}

	if (apol_infoflow_results_check_both(p, working_results, g->direction, results) < 0) {
		goto cleanup;
	}

	retval = 0;
      cleanup:
	apol_vector_destroy(&nodes);
	apol_vector_destroy(&working_results);
	return retval;
}

/*************** infoflow graph transitive analysis routines ***************/

/**
 * Prepare an infoflow graph for a transitive analysis by coloring its
 * nodes and setting its parent and distance.  For the start node
 * color it red; for all others color them white.
 *
 * @param p Policy handler, for reporting errors.
 * @param g Infoflow graph to initialize.
 * @param start Node from which to begin analysis.
 * @param q Queue of apol_infoflow_node_t pointers to which search.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_graph_trans_init(const apol_policy_t * p,
					  apol_infoflow_graph_t * g, apol_infoflow_node_t * start, apol_queue_t * q)
{
	size_t i;
	apol_infoflow_node_t *node;
	for (i = 0; i < apol_vector_get_size(g->nodes); i++) {
		node = (apol_infoflow_node_t *) apol_vector_get_element(g->nodes, i);
		node->parent = NULL;
		if (node == start) {
			node->color = APOL_INFOFLOW_COLOR_RED;
			node->distance = 0;
			if (apol_queue_insert(q, node) < 0) {
				ERR(p, "%s", strerror(ENOMEM));
				return -1;
			}
		} else {
			node->color = APOL_INFOFLOW_COLOR_WHITE;
			node->distance = INT_MAX;
		}
	}
	return 0;
}

/**
 * Prepare an infoflow graph for furher transitive analysis by
 * coloring its nodes and setting its parent and distance.  For the
 * start node color it grey; for all others color them white.
 *
 * @param p Policy handler, for reporting errors.
 * @param g Infoflow graph to initialize.
 * @param start Node from which to begin analysis.
 * @param q Queue of apol_infoflow_node_t pointers to which search.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_graph_trans_further_init(const apol_policy_t * p,
						  apol_infoflow_graph_t * g, apol_infoflow_node_t * start, apol_queue_t * q)
{
	size_t i;
	apol_infoflow_node_t *node;
	for (i = 0; i < apol_vector_get_size(g->nodes); i++) {
		node = (apol_infoflow_node_t *) apol_vector_get_element(g->nodes, i);
		node->parent = NULL;
		if (node == start) {
			node->color = APOL_INFOFLOW_COLOR_GREY;
			node->distance = 0;
			if (apol_queue_insert(q, node) < 0) {
				ERR(p, "%s", strerror(ENOMEM));
				return -1;
			}
		} else {
			node->color = APOL_INFOFLOW_COLOR_WHITE;
			node->distance = -1;
		}
	}
	return 0;
}

/**
 * Given a colored infoflow graph from apol_infoflow_analysis_trans(),
 * find the shortest path from the end node to the start node.
 * Allocate and return a vector of apol_infoflow_node_t that lists the
 * nodes from the end to start.
 *
 * @param p Policy from which infoflow graph was generated.
 * @param g Infoflow graph that has been colored.
 * @param start_node Starting node for the path
 * @param end_node Ending node to which to find a path.
 * @param path Reference to a vector that will be allocated and filled
 * with apol_infoflow_node_t pointers from the graph.  The path will
 * be in reverse order (i.e., from end node to a start node).  Upon
 * error this will be set to NULL.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_trans_path(const apol_policy_t * p,
				    apol_infoflow_graph_t * g,
				    apol_infoflow_node_t * start_node, apol_infoflow_node_t * end_node, apol_vector_t ** path)
{
	int retval = -1;
	apol_infoflow_node_t *next_node = end_node;
	if ((*path = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	while (1) {
		if (apol_vector_append(*path, next_node) < 0) {
			ERR(p, "%s", strerror(errno));
			goto cleanup;
		}
		if (next_node == start_node) {
			break;
		}
		if (next_node == NULL || apol_vector_get_size(*path) >= apol_vector_get_size(g->nodes)) {
			ERR(p, "%s", "Infinite loop in trans_path.");
			errno = EPERM;
			goto cleanup;
		}
		next_node = next_node->parent;
	}
	retval = 0;
      cleanup:
	if (retval != 0) {
		apol_vector_destroy(path);
	}
	return retval;
}

/**
 * Given a node within an infoflow graph, return the edge that
 * connects it to next_node.
 *
 * @param p Policy handler, for reporting errors.
 * @param g Infoflow graph from which to find edge.
 * @param node Starting node.
 * @param next_node Ending node.
 *
 * @return Edge connecting node to next_node, or NULL on error.
 */
static apol_infoflow_edge_t *apol_infoflow_trans_find_edge(const apol_policy_t * p,
							   apol_infoflow_graph_t * g,
							   apol_infoflow_node_t * node, apol_infoflow_node_t * next_node)
{
	apol_vector_t *v;
	apol_infoflow_edge_t *edge;
	size_t i;

	if (g->direction == APOL_INFOFLOW_OUT) {
		v = node->out_edges;
	} else {
		v = node->in_edges;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		edge = (apol_infoflow_edge_t *) apol_vector_get_element(v, i);
		if (g->direction == APOL_INFOFLOW_OUT) {
			if (edge->start_node == node && edge->end_node == next_node) {
				return edge;
			}
		} else {
			if (edge->end_node == node && edge->start_node == next_node) {
				return edge;
			}

		}
	}
	ERR(p, "%s", "Did not find an edge.");
	return NULL;
}

/**
 * Given a path of nodes, define a new infoflow result that represents
 * that path.  The given path is a list of nodes that must be in
 * reverse order (i.e., from end node to start node) and must have at
 * least 2 elements within.
 *
 * @param p Policy handler, for reporting errors.
 * @param g Graph from which the node path originated.
 * @param path Vector of apol_infoflow_node_t representing an infoflow
 * path.
 * @param end_type Ending type for the path.
 * @param result Reference pointer to where to store result.  The
 * caller is responsible for calling apol_infoflow_result_free() upon
 * the returned value.  Upon error this will be set to NULL.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_trans_define(const apol_policy_t * p,
				      apol_infoflow_graph_t * g,
				      apol_vector_t * path, const qpol_type_t * end_type, apol_infoflow_result_t ** result)
{
	apol_infoflow_step_t *step = NULL;
	size_t path_len = apol_vector_get_size(path), i;
	apol_infoflow_node_t *node, *next_node;
	apol_infoflow_edge_t *edge;
	int retval = -1, length = 0;
	*result = NULL;

	if (((*result) = calloc(1, sizeof(**result))) == NULL ||
	    ((*result)->steps = apol_vector_create_with_capacity(path_len, apol_infoflow_step_free)) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	(*result)->end_type = end_type;
	/* build in reverse order because path is from end node to
	 * start node */
	node = (apol_infoflow_node_t *) apol_vector_get_element(path, path_len - 1);
	(*result)->start_type = node->type;
	(*result)->direction = g->direction;
	for (i = path_len - 1; i > 0; i--, node = next_node) {
		next_node = (apol_infoflow_node_t *) apol_vector_get_element(path, i - 1);
		edge = apol_infoflow_trans_find_edge(p, g, node, next_node);
		if (edge == NULL) {
			goto cleanup;
		}
		length += edge->length;
		if ((step = calloc(1, sizeof(*step))) == NULL ||
		    (step->rules = apol_vector_create_from_vector(edge->rules, NULL, NULL, NULL)) == NULL ||
		    apol_vector_append((*result)->steps, step) < 0) {
			apol_infoflow_step_free(step);
			ERR(p, "%s", strerror(ENOMEM));
			return -1;
		}
		step->start_type = edge->start_node->type;
		step->end_type = edge->end_node->type;
		step->weight = APOL_PERMMAP_MAX_WEIGHT - edge->length + 1;
	}
	(*result)->length = length;
	retval = 0;
      cleanup:
	if (retval != 0) {
		infoflow_result_free(*result);
		*result = NULL;
	}
	return retval;
}

/**
 * Compares two apol_infoflow_step_t objects, returning 0 if they have
 * the same contents, non-zero or not.  This is a callback function to
 * apol_vector_compare().
 *
 * @param a First apol_infoflow_step_t to compare.
 * @param b Other apol_infoflow_step_t to compare.
 * @param data Unused.
 *
 * @return 0 if the steps are the same, non-zero if different.
 */
static int apol_infoflow_trans_step_comp(const void *a, const void *b, void *data __attribute__ ((unused)))
{
	const apol_infoflow_step_t *step_a = (const apol_infoflow_step_t *)a;
	const apol_infoflow_step_t *step_b = (const apol_infoflow_step_t *)b;
	size_t i;
	if (step_a->start_type != step_b->start_type) {
		return (int)((char *)step_a->start_type - (char *)step_b->start_type);
	}
	if (step_a->end_type != step_b->end_type) {
		return (int)((char *)step_a->end_type - (char *)step_b->end_type);
	}
	return apol_vector_compare(step_a->rules, step_b->rules, NULL, NULL, &i);
}

/**
 * Given a path, append to the results vector a new
 * apol_infoflow_result object - but only if there is not already a
 * result describing the same path.
 *
 * @param p Policy handler, for reporting errors.
 * @param g Infoflow graph to which create results.
 * @param path Vector of apol_infoflow_node_t describing a path from
 * an end node to a starting node.
 * @param end_type Ending type for the path.
 * @param results Vector of apol_infoflow_result_t to possibly append
 * a new result.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_trans_append(const apol_policy_t * p,
				      apol_infoflow_graph_t * g,
				      apol_vector_t * path, const qpol_type_t * end_type, apol_vector_t * results)
{
	apol_infoflow_result_t *new_r = NULL, *r;
	size_t i, j;
	int compval, retval = -1;

	if (apol_infoflow_trans_define(p, g, path, end_type, &new_r) < 0) {
		goto cleanup;
	}

	/* First we look for duplicate paths */
	for (i = 0; i < apol_vector_get_size(results); i++) {
		r = (apol_infoflow_result_t *) apol_vector_get_element(results, i);
		if (r->end_type != end_type ||
		    r->direction != new_r->direction || apol_vector_get_size(r->steps) != apol_vector_get_size(new_r->steps)) {
			break;
		}
		compval = apol_vector_compare(r->steps, new_r->steps, apol_infoflow_trans_step_comp, NULL, &j);
		/* found a dup TODO - make certain all of the object
		 * class / rules are kept */
		if (compval == 0) {
			infoflow_result_free(new_r);
			new_r = NULL;
			retval = 0;
			goto cleanup;
		}
	}

	/* If we are here the newly built path is unique. */
	if (apol_vector_append(results, new_r) < 0) {
		goto cleanup;
	}
	retval = 0;
      cleanup:
	if (retval != 0) {
		infoflow_result_free(new_r);
	}
	return retval;
}

/**
 * Given a start and end node, add a trans infoflow results to a
 * vector.  If a regular expression is compiled into the infoflow
 * graph, apply that regex match against candidate end node types
 * prior to creating result nodes.
 *
 * @param p Policy to analyze.
 * @param g Information flow graph to analyze.
 * @param start_node Starting node.
 * @param end_node Ending node.
 * @param results Non-NULL vector to which append infoflow result.
 * The caller is responsible for calling apol_infoflow_results_free()
 * upon each element afterwards.
 *
 * @return 0 on success (including no result actually added), or < 0
 * on error.
 */
static int apol_infoflow_analysis_trans_expand(const apol_policy_t * p,
					       apol_infoflow_graph_t * g,
					       apol_infoflow_node_t * start_node,
					       apol_infoflow_node_t * end_node, apol_vector_t * results)
{
	unsigned char isattr;
	apol_vector_t *path = NULL;
	int retval = -1, compval;

	if (qpol_type_get_isattr(p->p, end_node->type, &isattr) < 0) {
		goto cleanup;
	}
	assert(isattr == 0);
	if (start_node->type == end_node->type) {
		return 0;
	}
	compval = apol_infoflow_graph_compare(p, g, end_node->type);
	if (compval < 0) {
		goto cleanup;
	} else if (compval == 0) {
		return 0;
	}
	if (apol_infoflow_trans_path(p, g, start_node, end_node, &path) < 0 ||
	    apol_infoflow_trans_append(p, g, path, end_node->type, results) < 0) {
		goto cleanup;
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&path);
	return retval;
}

/**
 * Perform a transitive information flow analysis upon the given
 * infoflow graph starting from some particular node within the graph.
 *
 * This is a label correcting shortest path algorithm; see Bertsekas,
 * D. P., "A Simple and Fast Label Correcting Algorithm for Shortest
 * Paths," Networks, Vol. 23, pp. 703-709, 1993. for more information.
 * A label correcting algorithm is needed instead of the more common
 * Dijkstra label setting algorithm to correctly handle the the cycles
 * that are possible in these graphs.
 *
 * This algorithm finds the shortest path between a given start node
 * and all other nodes in the graph.  Any paths that it finds it
 * appends to the iflow_transitive_t structure. This is a basic label
 * correcting algorithm with 1 optimization.  It uses the D'Esopo-Pape
 * method for node selection in the node queue.  Why is this faster?
 * The paper referenced above says "No definitive explanation has been
 * given."  They have fancy graphs to show that it is faster though
 * and the important part is that the worst case isn't much worse that
 * N^2 - much better than an n^3 transitive closure.  Additionally,
 * most normal sparse graphs are significantly better than the worst
 * case.
 *
 * @param p Policy to analyze.
 * @param g Information flow graph to analyze.
 * @param start Node from which to begin search.
 * @param results Non-NULL vector to which append infoflow results.
 * The caller is responsible for calling apol_infoflow_results_free()
 * upon each element afterwards.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_analysis_trans_shortest_path(const apol_policy_t * p,
						      apol_infoflow_graph_t * g,
						      apol_infoflow_node_t * start, apol_vector_t * results)
{
	apol_vector_t *edge_list;
	apol_queue_t *queue = NULL;
	apol_infoflow_node_t *node, *cur_node;
	apol_infoflow_edge_t *edge;
	size_t i;
	int retval = -1;

	if ((queue = apol_queue_create()) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_infoflow_graph_trans_init(p, g, start, queue) < 0) {
		goto cleanup;
	}

	while ((cur_node = apol_queue_remove(queue)) != NULL) {
		cur_node->color = APOL_INFOFLOW_COLOR_GREY;
		if (g->direction == APOL_INFOFLOW_OUT) {
			edge_list = cur_node->out_edges;
		} else {
			edge_list = cur_node->in_edges;
		}
		for (i = 0; i < apol_vector_get_size(edge_list); i++) {
			edge = (apol_infoflow_edge_t *) apol_vector_get_element(edge_list, i);
			if (g->direction == APOL_INFOFLOW_OUT) {
				node = edge->end_node;
			} else {
				node = edge->start_node;
			}
			if (node == start) {
				continue;
			}

			if (node->distance > cur_node->distance + edge->length) {
				node->distance = cur_node->distance + edge->length;
				node->parent = cur_node;
				/* If this node has been inserted into
				 * the queue before insert it at the
				 * beginning, otherwise it goes to the
				 * end.  See the comment at the
				 * beginning of the function for
				 * why. */
				if (node->color != APOL_INFOFLOW_COLOR_RED) {
					if (node->color == APOL_INFOFLOW_COLOR_GREY) {
						if (apol_queue_push(queue, node) < 0) {
							ERR(p, "%s", strerror(ENOMEM));
							goto cleanup;
						}
					} else {
						if (apol_queue_insert(queue, node) < 0) {
							ERR(p, "%s", strerror(ENOMEM));
							goto cleanup;
						}
					}
					node->color = APOL_INFOFLOW_COLOR_RED;
				}
			}
		}
	}

	/* Find all of the paths and add them to the results vector */
	for (i = 0; i < apol_vector_get_size(g->nodes); i++) {
		cur_node = (apol_infoflow_node_t *) apol_vector_get_element(g->nodes, i);
		if (cur_node->parent == NULL || cur_node == start) {
			continue;
		}
		if (apol_infoflow_analysis_trans_expand(p, g, start, cur_node, results) < 0) {
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	apol_queue_destroy(&queue);
	return retval;
}

/**
 * Perform a transitive information flow analysis upon the given
 * infoflow graph.
 *
 * @param p Policy to analyze.
 * @param g Information flow graph to analyze.
 * @param start_type Type from which to begin search.
 * @param results Non-NULL vector to which append infoflow results.
 * The caller is responsible for calling apol_infoflow_results_free()
 * upon each element afterwards.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_infoflow_analysis_trans(const apol_policy_t * p,
					apol_infoflow_graph_t * g, const char *start_type, apol_vector_t * results)
{
	apol_vector_t *start_nodes = NULL;
	apol_infoflow_node_t *start_node;
	size_t i;
	int retval = -1;

	if (g->direction != APOL_INFOFLOW_IN && g->direction != APOL_INFOFLOW_OUT) {
		ERR(p, "%s", strerror(EINVAL));
		goto cleanup;
	}
	if ((start_nodes = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	if (apol_infoflow_graph_get_nodes_for_type(p, g, start_type, start_nodes) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(start_nodes); i++) {
		start_node = (apol_infoflow_node_t *) apol_vector_get_element(start_nodes, i);
		if (apol_infoflow_analysis_trans_shortest_path(p, g, start_node, results) < 0) {
			goto cleanup;
		}
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&start_nodes);
	return retval;
}

/**
 * Given a vector, allocate and return a new vector with the elements
 * shuffled about.  This will make a shallow copy of the original
 * vector's elements.
 *
 * @param p Policy handler, for error reporting.
 * @param g Transitive infoflow graph containing PRNG object.
 * @param v Vector to shuffle.
 *
 * @return A newly allocated vector with shuffled elements, or NULL
 * upon error.  The caller must call apol_vector_destroy() upon the
 * returned value.
 */
static apol_vector_t *apol_infoflow_trans_further_shuffle(const apol_policy_t * p, apol_infoflow_graph_t * g, apol_vector_t * v)
{
	size_t i, j, size;
	void **deck = NULL, *tmp;
	apol_vector_t *new_v = NULL;
	int retval = -1;
	size = apol_vector_get_size(v);
	if ((new_v = apol_vector_create_with_capacity(size, NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	if (size == 0) {
		retval = 0;
		goto cleanup;
	}
	if ((deck = malloc(size * sizeof(*deck))) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (i = 0; i < size; i++) {
		deck[i] = apol_vector_get_element(v, i);
	}
	for (i = size - 1; i > 0; i--) {
		j = (size_t) ((apol_infoflow_rand(g) / (RAND_MAX + 1.0)) * i);
		tmp = deck[i];
		deck[i] = deck[j];
		deck[j] = tmp;
	}
	for (i = 0; i < size; i++) {
		if (apol_vector_append(new_v, deck[i]) < 0) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}
	retval = 0;
      cleanup:
	free(deck);
	if (retval != 0) {
		apol_vector_destroy(&new_v);
	}
	return new_v;
}

static int apol_infoflow_analysis_trans_further(const apol_policy_t * p,
						apol_infoflow_graph_t * g, apol_infoflow_node_t * start, apol_vector_t * results)
{
	apol_vector_t *edge_list = NULL;
	apol_queue_t *queue = NULL;
	apol_infoflow_node_t *node, *cur_node;
	apol_infoflow_edge_t *edge;
	size_t i;
	int retval = -1;

	if ((queue = apol_queue_create()) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_infoflow_graph_trans_further_init(p, g, start, queue) < 0) {
		goto cleanup;
	}

	while ((cur_node = apol_queue_remove(queue)) != NULL) {
		if (cur_node != start &&
		    apol_vector_get_index(g->further_end, cur_node, NULL, NULL, &i) == 0 &&
		    apol_infoflow_analysis_trans_expand(p, g, start, cur_node, results) < 0) {
			goto cleanup;
		}
		cur_node->color = APOL_INFOFLOW_COLOR_BLACK;
		if (g->direction == APOL_INFOFLOW_OUT) {
			edge_list = cur_node->out_edges;
		} else {
			edge_list = cur_node->in_edges;
		}
		edge_list = apol_infoflow_trans_further_shuffle(p, g, edge_list);
		if (edge_list == NULL) {
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(edge_list); i++) {
			edge = (apol_infoflow_edge_t *) apol_vector_get_element(edge_list, i);
			if (g->direction == APOL_INFOFLOW_OUT) {
				node = edge->end_node;
			} else {
				node = edge->start_node;
			}
			if (node->color == APOL_INFOFLOW_COLOR_WHITE) {
				node->color = APOL_INFOFLOW_COLOR_GREY;
				node->distance = cur_node->distance + 1;
				node->parent = cur_node;
				if (apol_queue_push(queue, node) < 0) {
					ERR(p, "%s", strerror(ENOMEM));
					goto cleanup;
				}
			}
		}
		apol_vector_destroy(&edge_list);
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&edge_list);
	apol_queue_destroy(&queue);
	return retval;
}

/******************** infoflow analysis object routines ********************/

int apol_infoflow_analysis_do(const apol_policy_t * p, const apol_infoflow_analysis_t * ia, apol_vector_t ** v,
			      apol_infoflow_graph_t ** g)
{
	int retval = -1;
	if (v != NULL) {
		*v = NULL;
	}
	if (g != NULL) {
		*g = NULL;
	}
	if (p == NULL || ia == NULL || v == NULL || g == NULL || ia->mode == 0 || ia->direction == 0) {
		ERR(p, "%s", strerror(EINVAL));
		goto cleanup;
	}
	if (apol_infoflow_graph_create(p, ia, g) < 0) {
		goto cleanup;
	}
	INFO(p, "%s", "Searching information flow graph.");
	retval = apol_infoflow_analysis_do_more(p, *g, ia->type, v);
      cleanup:
	if (retval != 0) {
		apol_infoflow_graph_destroy(g);
	}
	return retval;
}

int apol_infoflow_analysis_do_more(const apol_policy_t * p, apol_infoflow_graph_t * g, const char *type, apol_vector_t ** v)
{
	const qpol_type_t *start_type;
	int retval = -1;
	if (v != NULL) {
		*v = NULL;
	}
	if (p == NULL || g == NULL || type == NULL || v == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		goto cleanup;
	}

	if (apol_query_get_type(p, type, &start_type) < 0) {
		goto cleanup;
	}

	if ((*v = apol_vector_create(infoflow_result_free)) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}

	if ((g->mode == APOL_INFOFLOW_MODE_DIRECT &&
	     apol_infoflow_analysis_direct(p, g, type, *v) < 0) ||
	    (g->mode == APOL_INFOFLOW_MODE_TRANS && apol_infoflow_analysis_trans(p, g, type, *v) < 0)) {
		goto cleanup;
	}

	retval = 0;
      cleanup:
	if (retval != 0) {
		apol_vector_destroy(v);
	}
	return retval;
}

int apol_infoflow_analysis_trans_further_prepare(const apol_policy_t * p,
						 apol_infoflow_graph_t * g, const char *start_type, const char *end_type)
{
	const qpol_type_t *stype, *etype;
	int retval = -1;

	apol_infoflow_srand(g);
	if (apol_query_get_type(p, start_type, &stype) < 0 || apol_query_get_type(p, end_type, &etype) < 0) {
		goto cleanup;
	}
	if (g->mode != APOL_INFOFLOW_MODE_TRANS) {
		ERR(p, "%s", "May only perform further infoflow analysis when the graph is transitive.");
		goto cleanup;
	}
	apol_vector_destroy(&g->further_start);
	apol_vector_destroy(&g->further_end);
	if ((g->further_start = apol_vector_create(NULL)) == NULL || (g->further_end = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	if (apol_infoflow_graph_get_nodes_for_type(p, g, start_type, g->further_start) < 0 ||
	    apol_infoflow_graph_get_nodes_for_type(p, g, end_type, g->further_end) < 0) {
		goto cleanup;
	}
	g->current_start = 0;
	retval = 0;
      cleanup:
	return retval;
}

int apol_infoflow_analysis_trans_further_next(const apol_policy_t * p, apol_infoflow_graph_t * g, apol_vector_t ** v)
{
	apol_infoflow_node_t *start_node;
	int retval = -1;
	if (p == NULL || g == NULL || v == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (*v == NULL) {
		*v = apol_vector_create(infoflow_result_free);
	}
	if (g->further_start == NULL) {
		ERR(p, "%s", "Infoflow graph was not prepared yet.");
		goto cleanup;
	}
	start_node = apol_vector_get_element(g->further_start, g->current_start);
	if (apol_infoflow_analysis_trans_further(p, g, start_node, *v) < 0) {
		goto cleanup;
	}
	g->current_start++;
	if (g->current_start >= apol_vector_get_size(g->further_start)) {
		g->current_start = 0;
	}
	retval = 0;
      cleanup:
	return retval;
}

apol_infoflow_analysis_t *apol_infoflow_analysis_create(void)
{
	return calloc(1, sizeof(apol_infoflow_analysis_t));
}

void apol_infoflow_analysis_destroy(apol_infoflow_analysis_t ** ia)
{
	if (*ia != NULL) {
		free((*ia)->type);
		free((*ia)->result);
		apol_vector_destroy(&(*ia)->intermed);
		apol_vector_destroy(&(*ia)->class_perms);
		free(*ia);
		*ia = NULL;
	}
}

int apol_infoflow_analysis_set_mode(const apol_policy_t * p, apol_infoflow_analysis_t * ia, unsigned int mode)
{
	switch (mode) {
	case APOL_INFOFLOW_MODE_DIRECT:
	case APOL_INFOFLOW_MODE_TRANS:
	{
		ia->mode = mode;
		break;
	}
	default:
	{
		ERR(p, "%s", strerror(EINVAL));
		return -1;
	}
	}
	return 0;
}

int apol_infoflow_analysis_set_dir(const apol_policy_t * p, apol_infoflow_analysis_t * ia, unsigned int dir)
{
	switch (dir) {
	case APOL_INFOFLOW_IN:
	case APOL_INFOFLOW_OUT:
	case APOL_INFOFLOW_BOTH:
	case APOL_INFOFLOW_EITHER:
	{
		ia->direction = dir;
		break;
	}
	default:
	{
		ERR(p, "%s", strerror(EINVAL));
		return -1;
	}
	}
	return 0;
}

int apol_infoflow_analysis_set_type(const apol_policy_t * p, apol_infoflow_analysis_t * ia, const char *name)
{
	if (name == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		return -1;
	}
	return apol_query_set(p, &ia->type, NULL, name);
}

static int compare_class_perm_by_class_name(const void *in_op, const void *class_name, void *unused __attribute__ ((unused)))
{
	const apol_obj_perm_t *op = (const apol_obj_perm_t *)in_op;
	const char *name = (const char *)class_name;

	return strcmp(apol_obj_perm_get_obj_name(op), name);
}

int apol_infoflow_analysis_append_intermediate(const apol_policy_t * policy, apol_infoflow_analysis_t * ia, const char *type)
{
	char *tmp = NULL;
	if (type == NULL) {
		apol_vector_destroy(&ia->intermed);
		return 0;
	}
	if (ia->intermed == NULL && (ia->intermed = apol_vector_create(free)) == NULL) {
		ERR(policy, "Error appending type to analysis: %s", strerror(ENOMEM));
		return -1;
	}
	if ((tmp = strdup(type)) == NULL || apol_vector_append(ia->intermed, tmp) < 0) {
		free(tmp);
		ERR(policy, "Error appending type to analysis: %s", strerror(ENOMEM));
		return -1;
	}
	return 0;
}

int apol_infoflow_analysis_append_class_perm(const apol_policy_t * p,
					     apol_infoflow_analysis_t * ia, const char *class_name, const char *perm_name)
{
	apol_obj_perm_t *op = NULL;
	size_t i;

	if (p == NULL || ia == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (class_name == NULL) {
		apol_vector_destroy(&ia->class_perms);
		return 0;
	}
	if (perm_name == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (ia->class_perms == NULL && (ia->class_perms = apol_vector_create(apol_obj_perm_free)) == NULL) {
		ERR(p, "%s", strerror(errno));
		return -1;
	}

	if (apol_vector_get_index(ia->class_perms, (void *)class_name, compare_class_perm_by_class_name, NULL, &i) < 0) {
		if (perm_name) {
			if ((op = apol_obj_perm_create()) == NULL) {
				ERR(p, "%s", strerror(errno));
				return -1;
			}
			if (apol_obj_perm_set_obj_name(op, class_name) ||
			    apol_obj_perm_append_perm(op, perm_name) || apol_vector_append(ia->class_perms, op)) {
				ERR(p, "%s", strerror(errno));
				apol_obj_perm_free(op);
				return -1;
			}
		} else {
			return 0;      /* nothing to clear; done */
		}
	} else {
		op = apol_vector_get_element(ia->class_perms, i);
		if (apol_obj_perm_append_perm(op, perm_name)) {
			ERR(p, "%s", strerror(errno));
			return -1;
		}
	}
	return 0;
}

int apol_infoflow_analysis_set_min_weight(const apol_policy_t * p
					  __attribute__ ((unused)), apol_infoflow_analysis_t * ia, int min_weight)
{
	if (min_weight <= 0) {
		ia->min_weight = 0;
	} else if (min_weight >= APOL_PERMMAP_MAX_WEIGHT) {
		ia->min_weight = APOL_PERMMAP_MAX_WEIGHT;
	} else {
		ia->min_weight = min_weight;
	}
	return 0;
}

int apol_infoflow_analysis_set_result_regex(const apol_policy_t * p, apol_infoflow_analysis_t * ia, const char *result)
{
	return apol_query_set(p, &ia->result, NULL, result);
}

/*************** functions to access infoflow results ***************/

unsigned int apol_infoflow_result_get_dir(const apol_infoflow_result_t * result)
{
	if (!result) {
		errno = EINVAL;
		return 0;
	}
	return result->direction;
}

const qpol_type_t *apol_infoflow_result_get_start_type(const apol_infoflow_result_t * result)
{
	if (!result) {
		errno = EINVAL;
		return NULL;
	}
	return result->start_type;
}

const qpol_type_t *apol_infoflow_result_get_end_type(const apol_infoflow_result_t * result)
{
	if (!result) {
		errno = EINVAL;
		return NULL;
	}
	return result->end_type;
}

unsigned int apol_infoflow_result_get_length(const apol_infoflow_result_t * result)
{
	if (!result) {
		errno = EINVAL;
		return 0;
	}
	assert(result->length != 0);
	return result->length;
}

const apol_vector_t *apol_infoflow_result_get_steps(const apol_infoflow_result_t * result)
{
	if (!result) {
		errno = EINVAL;
		return NULL;
	}
	return result->steps;
}

const qpol_type_t *apol_infoflow_step_get_start_type(const apol_infoflow_step_t * step)
{
	if (!step) {
		errno = EINVAL;
		return NULL;
	}
	return step->start_type;
}

const qpol_type_t *apol_infoflow_step_get_end_type(const apol_infoflow_step_t * step)
{
	if (!step) {
		errno = EINVAL;
		return NULL;
	}
	return step->end_type;
}

int apol_infoflow_step_get_weight(const apol_infoflow_step_t * step)
{
	if (!step) {
		errno = EINVAL;
		return -1;
	}
	return step->weight;
}

const apol_vector_t *apol_infoflow_step_get_rules(const apol_infoflow_step_t * step)
{
	if (!step) {
		errno = EINVAL;
		return NULL;
	}
	return step->rules;
}

/******************** protected functions ********************/

apol_infoflow_result_t *infoflow_result_create_from_infoflow_result(const apol_infoflow_result_t * result)
{
	apol_infoflow_result_t *new_r = NULL;
	apol_infoflow_step_t *step, *new_step;
	size_t i;
	int retval = -1;

	if ((new_r = calloc(1, sizeof(*new_r))) == NULL ||
	    (new_r->steps = apol_vector_create_with_capacity(apol_vector_get_size(result->steps), apol_infoflow_step_free)) == NULL)
	{
		goto cleanup;
	}
	new_r->start_type = result->start_type;
	new_r->end_type = result->end_type;
	new_r->direction = result->direction;
	new_r->length = result->length;
	for (i = 0; i < apol_vector_get_size(result->steps); i++) {
		step = (apol_infoflow_step_t *) apol_vector_get_element(result->steps, i);
		if ((new_step = calloc(1, sizeof(*new_step))) == NULL ||
		    (new_step->rules = apol_vector_create_from_vector(step->rules, NULL, NULL, NULL)) == NULL ||
		    apol_vector_append(new_r->steps, new_step) < 0) {
			apol_infoflow_step_free(new_step);
			goto cleanup;
		}
		new_step->start_type = step->start_type;
		new_step->end_type = step->end_type;
		new_step->weight = step->weight;
	}
	retval = 0;
      cleanup:
	if (retval != 0) {
		infoflow_result_free(new_r);
		return NULL;
	}
	return new_r;
}

void infoflow_result_free(void *result)
{
	if (result != NULL) {
		apol_infoflow_result_t *r = (apol_infoflow_result_t *) result;
		apol_vector_destroy(&r->steps);
		free(r);
	}
}
