/**
 * @file
 *
 * Routines to perform a domain transition analysis.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2005-2007 Tresys Technology, LLC
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
#include "domain-trans-analysis-internal.h"
#include <apol/domain-trans-analysis.h>
#include <apol/bst.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

/* private data structure definitions */
struct apol_domain_trans_table
{
	apol_bst_t *domain_table;
	apol_bst_t *entrypoint_table;
};

typedef struct dom_node
{
	const qpol_type_t *type;
	apol_bst_t *process_transition_tree;
	apol_bst_t *entrypoint_tree;
	apol_vector_t *setexec_rules;
} dom_node_t;

typedef struct ep_node
{
	const qpol_type_t *type;
	apol_bst_t *execute_tree;
	apol_bst_t *type_transition_tree;
} ep_node_t;

typedef struct avrule_node
{
	const qpol_type_t *type;
	const qpol_avrule_t *rule;
	bool used;
} avrule_node_t;

typedef struct terule_node
{
	const qpol_type_t *src;
	const qpol_type_t *dflt;
	const qpol_terule_t *rule;
	bool used;
} terule_node_t;

/* public data structure definitions */
struct apol_domain_trans_analysis
{
	unsigned char direction;
	unsigned char valid;
	char *start_type;
	char *result;
	apol_vector_t *access_types;
	apol_vector_t *access_classes;
	apol_vector_t *access_perms;
	regex_t *result_regex;
};

struct apol_domain_trans_result
{
	const qpol_type_t *start_type;
	const qpol_type_t *ep_type;
	const qpol_type_t *end_type;
	apol_vector_t *proc_trans_rules;
	apol_vector_t *ep_rules;
	apol_vector_t *exec_rules;
	apol_vector_t *setexec_rules;
	apol_vector_t *type_trans_rules;
	bool valid;
	/** if access filters used list of rules that satisfy
	 * the filter criteria (of type qpol_avrule_t) */
	apol_vector_t *access_rules;
};

/* private functions */
/* avrule_node */
static int avrule_node_cmp(const void *a, const void *b, void *data __attribute__ ((unused)))
{
	const avrule_node_t *an = a;
	const avrule_node_t *bn = b;
	ssize_t retv = (const char *)an->type - (const char *)bn->type;
	if (retv > 0)
		return 1;
	else if (retv < 0)
		return -1;
	retv = (const char *)an->rule - (const char *)bn->rule;
	if (retv > 0)
		return 1;
	else if (retv < 0)
		return -1;
	return 0;
}

static int avrule_node_reset(void *a, void *b __attribute__ ((unused)))
{
	avrule_node_t *an = a;
	if (!a)
		return -1;
	an->used = false;
	return 0;
}

static avrule_node_t *avrule_node_create(const qpol_type_t * type, const qpol_avrule_t * rule)
{
	avrule_node_t *n = calloc(1, sizeof(*n));
	if (!n)
		return NULL;

	n->type = type;
	n->rule = rule;

	return n;
}

/* terule_node */
static int terule_node_cmp(const void *a, const void *b, void *data __attribute__ ((unused)))
{
	const terule_node_t *an = a;
	const terule_node_t *bn = b;
	ssize_t retv = (const char *)an->src - (const char *)bn->src;
	if (retv > 0)
		return 1;
	else if (retv < 0)
		return -1;
	retv = (const char *)an->dflt - (const char *)bn->dflt;
	if (retv > 0)
		return 1;
	else if (retv < 0)
		return -1;
	retv = (const char *)an->rule - (const char *)bn->rule;
	if (retv > 0)
		return 1;
	else if (retv < 0)
		return -1;
	return 0;
}

static int terule_node_reset(void *a, void *b __attribute__ ((unused)))
{
	terule_node_t *an = a;
	if (!a)
		return -1;
	an->used = false;
	return 0;
}

static terule_node_t *terule_node_create(const qpol_type_t * src, const qpol_type_t * dflt, const qpol_terule_t * rule)
{
	terule_node_t *n = calloc(1, sizeof(*n));
	if (!n)
		return NULL;

	n->src = src;
	n->dflt = dflt;
	n->rule = rule;

	return n;
}

/* dom_node */
static int dom_node_cmp(const void *a, const void *b, void *data __attribute__ ((unused)))
{
	const dom_node_t *an = a;
	const dom_node_t *bn = b;

	if ((const char *)(an->type) < (const char *)(bn->type))
		return -1;
	else if ((const char *)(an->type) > (const char *)(bn->type))
		return 1;
	return 0;
}

static void dom_node_free(void *x)
{
	if (!x)
		return;
	apol_bst_destroy(&(((dom_node_t *) x)->process_transition_tree));
	apol_bst_destroy(&(((dom_node_t *) x)->entrypoint_tree));
	apol_vector_destroy(&(((dom_node_t *) x)->setexec_rules));
	free(x);
}

static int dom_node_reset(void *a, void *b __attribute__ ((unused)))
{
	dom_node_t *an = a;
	if (!a)
		return -1;

	if (apol_bst_inorder_map(an->process_transition_tree, avrule_node_reset, NULL) < 0)
		return -1;
	if (apol_bst_inorder_map(an->entrypoint_tree, avrule_node_reset, NULL) < 0)
		return -1;

	return 0;
}

static dom_node_t *dom_node_create(const qpol_type_t * type)
{
	dom_node_t *n = calloc(1, sizeof(*n));
	if (!n)
		return NULL;

	n->type = type;
	if (!(n->process_transition_tree = apol_bst_create(avrule_node_cmp, free)) ||
	    !(n->entrypoint_tree = apol_bst_create(avrule_node_cmp, free)) || !(n->setexec_rules = apol_vector_create(NULL))) {
		apol_bst_destroy(&n->process_transition_tree);
		apol_bst_destroy(&n->entrypoint_tree);
		apol_vector_destroy(&n->setexec_rules);
		free(n);
		return NULL;
	}

	return n;
}

/* ep_node */
static int ep_node_cmp(const void *a, const void *b, void *data __attribute__ ((unused)))
{
	const ep_node_t *an = a;
	const ep_node_t *bn = b;

	if ((const char *)(an->type) < (const char *)(bn->type))
		return -1;
	else if ((const char *)(an->type) > (const char *)(bn->type))
		return 1;
	return 0;
}

static void ep_node_free(void *x)
{
	if (!x)
		return;
	apol_bst_destroy(&(((ep_node_t *) x)->type_transition_tree));
	apol_bst_destroy(&(((ep_node_t *) x)->execute_tree));
	free(x);
}

static int ep_node_reset(void *a, void *b __attribute__ ((unused)))
{
	ep_node_t *an = a;
	if (!a)
		return -1;

	if (apol_bst_inorder_map(an->execute_tree, avrule_node_reset, NULL) < 0)
		return -1;
	if (apol_bst_inorder_map(an->type_transition_tree, terule_node_reset, NULL) < 0)
		return -1;
	return 0;
}

static ep_node_t *ep_node_create(const qpol_type_t * type)
{
	ep_node_t *n = calloc(1, sizeof(*n));
	if (!n)
		return NULL;

	n->type = type;
	if (!(n->execute_tree = apol_bst_create(avrule_node_cmp, free)) ||
	    !(n->type_transition_tree = apol_bst_create(terule_node_cmp, free))) {
		apol_bst_destroy(&n->execute_tree);
		apol_bst_destroy(&n->type_transition_tree);
		free(n);
		return NULL;
	}

	return n;
}

/* table */
static apol_domain_trans_table_t *apol_domain_trans_table_new(apol_policy_t * policy)
{
	apol_domain_trans_table_t *new_table = NULL;
	int error;

	if (!policy) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}

	new_table = (apol_domain_trans_table_t *) calloc(1, sizeof(apol_domain_trans_table_t));
	if (!new_table) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto cleanup;
	}

	if (!(new_table->domain_table = apol_bst_create(dom_node_cmp, dom_node_free))) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto cleanup;
	}
	if (!(new_table->entrypoint_table = apol_bst_create(ep_node_cmp, ep_node_free))) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto cleanup;
	}

	return new_table;
      cleanup:
	domain_trans_table_destroy(&new_table);
	errno = error;
	return NULL;
}

static int table_add_avrule(apol_policy_t * policy, apol_domain_trans_table_t * dta_table, const qpol_avrule_t * rule)
{
	qpol_policy_t *qp = apol_policy_get_qpol(policy);
	const qpol_type_t *src;
	const qpol_type_t *tgt;
	qpol_avrule_get_source_type(qp, rule, &src);
	qpol_avrule_get_target_type(qp, rule, &tgt);
	apol_vector_t *sources = apol_query_expand_type(policy, src);
	apol_vector_t *targets = apol_query_expand_type(policy, tgt);
	bool exec = false, ep = false, proc_trans = false, setexec = false;
	qpol_iterator_t *iter = NULL;
	int error = 0;
	qpol_avrule_get_perm_iter(qp, rule, &iter);
	if (!iter || !sources || !targets) {
		error = errno;
		goto err;
	}

	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		void *x;
		qpol_iterator_get_item(iter, &x);
		char *perm = x;
		if (!strcmp("execute", perm))
			exec = true;
		if (!strcmp("entrypoint", perm))
			ep = true;
		if (!strcmp("transition", perm))
			proc_trans = true;
		if (!strcmp("setexec", perm))
			setexec = true;
		free(x);
	}
	qpol_iterator_destroy(&iter);

	if (proc_trans || ep || setexec) {
		for (size_t i = 0; i < apol_vector_get_size(sources); i++) {
			dom_node_t *dnode = NULL;
			dom_node_t dummy = { apol_vector_get_element(sources, i), NULL, NULL, NULL };
			if (apol_bst_get_element(dta_table->domain_table, &dummy, NULL, (void **)&dnode)) {
				dom_node_t *new_dnode = NULL;
				if (!(new_dnode = dom_node_create(dummy.type)) ||
				    apol_bst_insert(dta_table->domain_table, (void *)new_dnode, NULL)) {
					error = errno;
					dom_node_free(new_dnode);
					goto err;
				}
				dnode = new_dnode;
			}
			if (setexec) {
				if (apol_vector_append_unique(dnode->setexec_rules, (void *)rule, NULL, NULL)) {
					error = errno;
					goto err;
				}
			}
			for (size_t j = 0; j < apol_vector_get_size(targets); j++) {
				if (proc_trans) {
					avrule_node_t *new_node =
						avrule_node_create((const qpol_type_t *)apol_vector_get_element(targets, j), rule);
					if (!new_node ||
					    apol_bst_insert_and_get(dnode->process_transition_tree, (void **)&new_node, NULL) < 0) {
						error = errno;
						free(new_node);
						goto err;
					}
				}
				if (ep) {
					avrule_node_t *new_node =
						avrule_node_create((const qpol_type_t *)apol_vector_get_element(targets, j), rule);
					if (!new_node ||
					    apol_bst_insert_and_get(dnode->entrypoint_tree, (void **)&new_node, NULL) < 0) {
						error = errno;
						free(new_node);
						goto err;
					}
				}
			}
		}
	}
	if (exec) {
		for (size_t i = 0; i < apol_vector_get_size(targets); i++) {
			ep_node_t *enode = NULL;
			ep_node_t dummy = { apol_vector_get_element(targets, i), NULL, NULL };
			if (apol_bst_get_element(dta_table->entrypoint_table, &dummy, NULL, (void **)&enode)) {
				ep_node_t *new_enode = NULL;
				if (!(new_enode = ep_node_create(dummy.type)) ||
				    apol_bst_insert(dta_table->entrypoint_table, (void *)new_enode, NULL)) {
					error = errno;
					ep_node_free(new_enode);
					goto err;
				}
				enode = new_enode;
			}
			for (size_t j = 0; j < apol_vector_get_size(sources); j++) {
				avrule_node_t *new_node =
					avrule_node_create((const qpol_type_t *)apol_vector_get_element(sources, j), rule);
				if (!new_node || apol_bst_insert_and_get(enode->execute_tree, (void **)&new_node, NULL) < 0) {
					error = errno;
					free(new_node);
					goto err;
				}
			}
		}
	}

	apol_vector_destroy(&sources);
	apol_vector_destroy(&targets);
	return 0;

      err:
	qpol_iterator_destroy(&iter);
	apol_vector_destroy(&sources);
	apol_vector_destroy(&targets);
	errno = error;
	return -1;
}

static int table_add_terule(apol_policy_t * policy, apol_domain_trans_table_t * dta_table, const qpol_terule_t * rule)
{
	qpol_policy_t *qp = apol_policy_get_qpol(policy);
	const qpol_type_t *src;
	const qpol_type_t *tgt;
	const qpol_type_t *dflt;
	qpol_terule_get_source_type(qp, rule, &src);
	qpol_terule_get_target_type(qp, rule, &tgt);
	qpol_terule_get_default_type(qp, rule, &dflt);
	apol_vector_t *sources = apol_query_expand_type(policy, src);
	apol_vector_t *targets = apol_query_expand_type(policy, tgt);
	int error = 0;
	for (size_t i = 0; i < apol_vector_get_size(targets); i++) {
		ep_node_t *enode = NULL;
		ep_node_t dummy = { apol_vector_get_element(targets, i), NULL, NULL };
		if (apol_bst_get_element(dta_table->entrypoint_table, &dummy, NULL, (void **)&enode)) {
			ep_node_t *new_enode = NULL;
			if (!(new_enode = ep_node_create(dummy.type)) ||
			    apol_bst_insert(dta_table->entrypoint_table, (void *)new_enode, NULL)) {
				error = errno;
				ep_node_free(new_enode);
				goto err;
			}
			enode = new_enode;
		}
		for (size_t j = 0; j < apol_vector_get_size(sources); j++) {
			terule_node_t *new_node =
				terule_node_create((const qpol_type_t *)apol_vector_get_element(sources, j), dflt, rule);
			if (apol_bst_insert_and_get(enode->type_transition_tree, (void **)&new_node, NULL) < 0) {
				error = errno;
				free(new_node);
				goto err;
			}
		}
	}

	apol_vector_destroy(&sources);
	apol_vector_destroy(&targets);
	return 0;
      err:
	apol_vector_destroy(&sources);
	apol_vector_destroy(&targets);
	errno = error;
	return -1;
}

/* result */
apol_domain_trans_result_t *domain_trans_result_create()
{
	apol_domain_trans_result_t *res = calloc(1, sizeof(*res));
	if (!res)
		return NULL;

	int error = 0;
	if (!(res->proc_trans_rules = apol_vector_create(NULL)) || !(res->ep_rules = apol_vector_create(NULL)) ||
	    !(res->exec_rules = apol_vector_create(NULL)) || !(res->setexec_rules = apol_vector_create(NULL)) ||
	    !(res->type_trans_rules = apol_vector_create(NULL))) {
		error = errno;
		goto err;
	}

	return res;
      err:
	apol_domain_trans_result_destroy(&res);
	errno = error;
	return NULL;
}

/* public functions */
/* table */
int apol_policy_build_domain_trans_table(apol_policy_t * policy)
{
	int error = 0;
	apol_avrule_query_t *avq = NULL;
	apol_terule_query_t *teq = NULL;
	apol_vector_t *avrules = NULL;
	apol_vector_t *terules = NULL;

	if (!policy) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (policy->domain_trans_table) {
		return 0;	       /* already built */
	}

	apol_domain_trans_table_t *dta_table = policy->domain_trans_table = apol_domain_trans_table_new(policy);
	if (!policy->domain_trans_table) {
		error = errno;
		goto err;
	}

	avq = apol_avrule_query_create();
	apol_avrule_query_set_rules(policy, avq, QPOL_RULE_ALLOW);
	apol_avrule_query_append_class(policy, avq, "file");
	apol_avrule_query_append_class(policy, avq, "process");
	apol_avrule_query_append_perm(policy, avq, "execute");
	apol_avrule_query_append_perm(policy, avq, "entrypoint");
	apol_avrule_query_append_perm(policy, avq, "transition");
	apol_avrule_query_append_perm(policy, avq, "setexec");
	if (apol_avrule_get_by_query(policy, avq, &avrules)) {
		error = errno;
		goto err;
	}
	apol_avrule_query_destroy(&avq);
	for (size_t i = 0; i < apol_vector_get_size(avrules); i++) {
		if (table_add_avrule(policy, dta_table, (const qpol_avrule_t *)apol_vector_get_element(avrules, i))) {
			error = errno;
			goto err;
		}
	}
	apol_vector_destroy(&avrules);

	teq = apol_terule_query_create();
	apol_terule_query_set_rules(policy, teq, QPOL_RULE_TYPE_TRANS);
	apol_terule_query_append_class(policy, teq, "process");
	if (apol_terule_get_by_query(policy, teq, &terules)) {
		error = errno;
		goto err;
	}
	apol_terule_query_destroy(&teq);
	for (size_t i = 0; i < apol_vector_get_size(terules); i++) {
		if (table_add_terule(policy, dta_table, (const qpol_terule_t *)apol_vector_get_element(terules, i))) {
			error = errno;
			goto err;
		}
	}
	apol_vector_destroy(&terules);

	return 0;

      err:
	apol_avrule_query_destroy(&avq);
	apol_vector_destroy(&avrules);
	apol_terule_query_destroy(&teq);
	apol_vector_destroy(&terules);
	domain_trans_table_destroy(&dta_table);
	policy->domain_trans_table = NULL;
	errno = error;
	return -1;
}

int apol_policy_domain_trans_table_build(apol_policy_t * policy)
{
	return apol_policy_build_domain_trans_table(policy);
}

void domain_trans_table_destroy(apol_domain_trans_table_t ** table)
{
	if (!table || !(*table))
		return;

	apol_bst_destroy(&(*table)->domain_table);
	apol_bst_destroy(&(*table)->entrypoint_table);
	free(*table);
	*table = NULL;
}

void apol_policy_reset_domain_trans_table(apol_policy_t * policy)
{
	if (!policy || !policy->domain_trans_table)
		return;
	apol_bst_inorder_map(policy->domain_trans_table->domain_table, dom_node_reset, NULL);
	apol_bst_inorder_map(policy->domain_trans_table->entrypoint_table, ep_node_reset, NULL);
	return;
}

void apol_domain_trans_table_reset(apol_policy_t * policy)
{
	apol_policy_reset_domain_trans_table(policy);
}

/* analysis */
apol_domain_trans_analysis_t *apol_domain_trans_analysis_create(void)
{
	apol_domain_trans_analysis_t *new_dta = NULL;
	int error = 0;

	if (!(new_dta = calloc(1, sizeof(apol_domain_trans_analysis_t)))) {
		error = errno;
		goto err;
	}

	new_dta->valid = APOL_DOMAIN_TRANS_SEARCH_VALID;	/* by default search only valid transitions */

	return new_dta;

      err:
	apol_domain_trans_analysis_destroy(&new_dta);
	errno = error;
	return NULL;
}

void apol_domain_trans_analysis_destroy(apol_domain_trans_analysis_t ** dta)
{
	if (!dta || !(*dta))
		return;

	free((*dta)->start_type);
	free((*dta)->result);
	apol_vector_destroy(&((*dta)->access_types));
	apol_vector_destroy(&((*dta)->access_classes));
	apol_vector_destroy(&((*dta)->access_perms));
	apol_regex_destroy(&((*dta)->result_regex));
	free(*dta);
	*dta = NULL;
}

int apol_domain_trans_analysis_set_direction(const apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
					     unsigned char direction)
{
	if (!dta || (direction != APOL_DOMAIN_TRANS_DIRECTION_FORWARD && direction != APOL_DOMAIN_TRANS_DIRECTION_REVERSE)) {
		ERR(policy, "Error setting analysis direction: %s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	dta->direction = direction;

	return 0;
}

int apol_domain_trans_analysis_set_valid(const apol_policy_t * policy, apol_domain_trans_analysis_t * dta, unsigned char valid)
{
	if (!dta || valid & ~(APOL_DOMAIN_TRANS_SEARCH_BOTH)) {
		ERR(policy, "Error setting analysis validity flag: %s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	dta->valid = valid;

	return 0;
}

int apol_domain_trans_analysis_set_start_type(const apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
					      const char *type_name)
{
	char *tmp = NULL;
	int error = 0;

	if (!dta || !type_name) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!(tmp = strdup(type_name))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		errno = error;
		return -1;
	}

	free(dta->start_type);
	dta->start_type = tmp;

	return 0;
}

int apol_domain_trans_analysis_set_result_regex(const apol_policy_t * policy, apol_domain_trans_analysis_t * dta, const char *regex)
{
	if (!dta) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!regex) {
		apol_regex_destroy(&dta->result_regex);
		return 0;
	}

	return apol_query_set(policy, &dta->result, &dta->result_regex, regex);
}

int apol_domain_trans_analysis_append_access_type(const apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
						  const char *type_name)
{
	char *tmp = NULL;
	int error = 0;

	if (!dta) {
		ERR(policy, "Error appending type to analysis: %s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!type_name) {
		apol_vector_destroy(&dta->access_types);
		return 0;
	}

	if (!dta->access_types) {
		if (!(dta->access_types = apol_vector_create(free))) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			errno = error;
			return -1;
		}
	}

	if (!(tmp = strdup(type_name))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		errno = error;
		return -1;
	}

	if (apol_vector_append(dta->access_types, tmp)) {
		error = errno;
		free(tmp);
		ERR(policy, "%s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

int apol_domain_trans_analysis_append_class_perm(const apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
						 const char *class_name, const char *perm_name)
{
	if (apol_domain_trans_analysis_append_class(policy, dta, class_name))
		return -1;
	return apol_domain_trans_analysis_append_perm(policy, dta, perm_name);
}

int apol_domain_trans_analysis_append_class(const apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
					    const char *class_name)
{
	char *tmp = NULL;
	int error = 0;

	if (!dta) {
		ERR(policy, "Error appending class to analysis: %s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!class_name) {
		apol_vector_destroy(&dta->access_classes);
		return 0;
	}

	if (!dta->access_classes) {
		if (!(dta->access_classes = apol_vector_create(free))) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			errno = error;
			return -1;
		}
	}

	if (!(tmp = strdup(class_name))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		errno = error;
		return -1;
	}

	if (apol_vector_append(dta->access_classes, tmp)) {
		error = errno;
		free(tmp);
		ERR(policy, "%s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

int apol_domain_trans_analysis_append_perm(const apol_policy_t * policy, apol_domain_trans_analysis_t * dta, const char *perm_name)
{
	char *tmp = NULL;
	int error = 0;

	if (!dta) {
		ERR(policy, "Error appending perm to analysis: %s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!perm_name) {
		apol_vector_destroy(&dta->access_perms);
		return 0;
	}

	if (!dta->access_perms) {
		if (!(dta->access_perms = apol_vector_create(free))) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			errno = error;
			return -1;
		}
	}

	if (!(tmp = strdup(perm_name))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		errno = error;
		return -1;
	}

	if (apol_vector_append(dta->access_perms, tmp)) {
		error = errno;
		free(tmp);
		ERR(policy, "%s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

static bool requires_setexec_or_type_trans(apol_policy_t * policy)
{
	const qpol_policy_t *qp = apol_policy_get_qpol(policy);
	unsigned int policy_version = 0;
	qpol_policy_get_policy_version(qp, &policy_version);
	int is_modular = qpol_policy_has_capability(policy->p, QPOL_CAP_MODULES);
	return (policy_version >= 15 || is_modular);
}

struct rule_map_data
{
	const qpol_type_t *search;
	const qpol_type_t *dflt;
	apol_vector_t *node_list;
	bool is_avnode;
};

static int node_list_map_fn(void *node, void *data)
{
	struct rule_map_data *rm = data;
	if (rm->is_avnode) {
		avrule_node_t *anode = node;
		if (anode->type == rm->search && !anode->used)
			if (apol_vector_append(rm->node_list, node))
				return -1;
		return 0;
	} else {
		terule_node_t *tnode = node;
		if ((!rm->search || (rm->search == tnode->src)) && (!rm->dflt || (rm->dflt == tnode->dflt)) &&
		    rm->search != rm->dflt && !tnode->used)
			if (apol_vector_append(rm->node_list, node))
				return -1;
		return 0;
	}
}

static apol_vector_t *find_avrules_in_node(void *node, unsigned int rule_type, const qpol_type_t * search)
{
	int error = 0;
	apol_vector_t *rule_nodes = apol_vector_create(NULL);	//shallow copies only
	struct rule_map_data data = { search, NULL, rule_nodes, true };
	switch (rule_type) {
	case APOL_DOMAIN_TRANS_RULE_PROC_TRANS:
	{
		dom_node_t *dnode = node;
		if (apol_bst_inorder_map(dnode->process_transition_tree, node_list_map_fn, (void *)&data) < 0) {
			error = errno;
			goto err;
		}
		break;
	}
	case APOL_DOMAIN_TRANS_RULE_ENTRYPOINT:
	{
		dom_node_t *dnode = node;
		if (apol_bst_inorder_map(dnode->entrypoint_tree, node_list_map_fn, (void *)&data) < 0) {
			error = errno;
			goto err;
		}
		break;
	}
	case APOL_DOMAIN_TRANS_RULE_EXEC:
	{
		ep_node_t *enode = node;
		if (apol_bst_inorder_map(enode->execute_tree, node_list_map_fn, (void *)&data) < 0) {
			error = errno;
			goto err;
		}
		break;
	}
	default:
	{
		error = EINVAL;
		goto err;
	}
	}

	return rule_nodes;

      err:
	apol_vector_destroy(&rule_nodes);
	errno = error;
	return NULL;
}

static apol_vector_t *find_terules_in_node(ep_node_t * node, const qpol_type_t * search, const qpol_type_t * dflt)
{
	int error = 0;
	apol_vector_t *rule_nodes = apol_vector_create(NULL);	//shallow copies only
	struct rule_map_data data = { search, dflt, rule_nodes, false };
	if (apol_bst_inorder_map(node->type_transition_tree, node_list_map_fn, (void *)&data) < 0) {
		error = errno;
		goto err;
	}

	return rule_nodes;

      err:
	apol_vector_destroy(&rule_nodes);
	errno = error;
	return NULL;
}

static apol_domain_trans_result_t *find_result(apol_vector_t * local_results, const qpol_type_t * src, const qpol_type_t * tgt,
					       const qpol_type_t * dflt)
{
	for (size_t i = 0; i < apol_vector_get_size(local_results); i++) {
		apol_domain_trans_result_t *res = apol_vector_get_element(local_results, i);
		if (res->start_type == src && res->end_type == dflt && res->ep_type == tgt)
			return res;
	}
	return NULL;
}

static int domain_trans_table_find_orphan_type_transitions(apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
							   apol_vector_t * local_results)
{
	int error = 0;
	const qpol_type_t *search = NULL;
	qpol_policy_get_type_by_name(apol_policy_get_qpol(policy), dta->start_type, &search);
	apol_domain_trans_result_t *tmp_result = NULL;
	//walk ep table
	apol_vector_t *epnodes = apol_bst_get_vector(policy->domain_trans_table->entrypoint_table, 0);
	if (!epnodes)
		return -1;
	for (size_t i = 0; i < apol_vector_get_size(epnodes); i++) {
		ep_node_t *node = apol_vector_get_element(epnodes, i);
		//find any unused type transitions
		apol_vector_t *ttnodes = NULL;
		if (dta->direction == APOL_DOMAIN_TRANS_DIRECTION_FORWARD)
			ttnodes = find_terules_in_node(node, search, NULL);
		else
			ttnodes = find_terules_in_node(node, NULL, search);
		for (size_t j = 0; j < apol_vector_get_size(ttnodes); j++) {
			bool add = false;
			terule_node_t *tn = apol_vector_get_element(ttnodes, j);
			tn->used = true;
			//if missing an entrypoint rule this transition may have already been added to the results
			tmp_result = find_result(local_results, tn->src, node->type, tn->dflt);
			if (!tmp_result) {
				add = true;
				tmp_result = domain_trans_result_create();
			}
			if (!tmp_result) {
				error = errno;
				apol_vector_destroy(&ttnodes);
				goto err;
			}
			tmp_result->start_type = tn->src;
			tmp_result->end_type = tn->dflt;
			tmp_result->ep_type = node->type;
			//check for exec
			apol_vector_t *execrules =
				find_avrules_in_node((void *)node, APOL_DOMAIN_TRANS_RULE_EXEC, tmp_result->start_type);
			for (size_t k = 0; k < apol_vector_get_size(execrules); k++) {
				avrule_node_t *n = apol_vector_get_element(execrules, k);
				if (apol_vector_append(tmp_result->exec_rules, (void *)n->rule)) {
					error = errno;
					apol_vector_destroy(&execrules);
					if (!add)
						tmp_result = NULL;
					goto err;
				}
			}
			apol_vector_destroy(&execrules);
			//check for proc_trans and setexec
			dom_node_t dummy = { tmp_result->start_type, NULL, NULL, NULL };
			dom_node_t *start_node = NULL;
			apol_bst_get_element(policy->domain_trans_table->domain_table, (void *)&dummy, NULL, (void **)&start_node);
			if (start_node) {
				//only copy setexec_rules if a new result will be added
				if (add && apol_vector_get_size(start_node->setexec_rules)) {
					if (apol_vector_cat(tmp_result->setexec_rules, start_node->setexec_rules)) {
						error = errno;
						goto err;
					}
				}
				//add any unused proc_trans rules
				apol_vector_t *proc_trans_rules =
					find_avrules_in_node((void *)start_node, APOL_DOMAIN_TRANS_RULE_PROC_TRANS,
							     tmp_result->end_type);
				for (size_t k = 0; k < apol_vector_get_size(proc_trans_rules); k++) {
					avrule_node_t *avr = apol_vector_get_element(proc_trans_rules, k);
					if (apol_vector_append(tmp_result->proc_trans_rules, (void *)avr->rule)) {
						error = errno;
						if (!add)
							tmp_result = NULL;
						apol_vector_destroy(&proc_trans_rules);
						goto err;
					}
				}
				apol_vector_destroy(&proc_trans_rules);
				apol_vector_sort_uniquify(tmp_result->proc_trans_rules, NULL, NULL);
			}
			if (add) {
				if (apol_vector_append(local_results, (void *)tmp_result)) {
					error = errno;
					goto err;
				}
			}
			tmp_result = NULL;
		}
		apol_vector_destroy(&ttnodes);
	}
	apol_vector_destroy(&epnodes);

	return 0;

      err:
	apol_vector_destroy(&epnodes);
	apol_domain_trans_result_destroy(&tmp_result);
	errno = error;
	return -1;
}

static int domain_trans_table_get_all_forward_trans(apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
						    apol_vector_t * local_results, const qpol_type_t * start_type)
{
	int error = 0;
	//create template result this will hold common data for each step and be copied as needed
	apol_domain_trans_result_t *tmpl_result = domain_trans_result_create();
	if (!tmpl_result) {
		error = errno;
		goto err;
	}
	//find start node
	dom_node_t dummy = { start_type, NULL, NULL, NULL };
	dom_node_t *start_node = NULL;
	apol_bst_get_element(policy->domain_trans_table->domain_table, (void *)&dummy, NULL, (void **)&start_node);
	if (start_node) {
		tmpl_result->start_type = start_type;
		//if needed and present record setexec
		if (requires_setexec_or_type_trans(policy) && apol_vector_get_size(start_node->setexec_rules)) {
			if (apol_vector_cat(tmpl_result->setexec_rules, start_node->setexec_rules)) {
				error = errno;
				goto err;
			}
		}
		//check all proc trans to build list of end types
		apol_vector_t *proc_trans_rules = apol_bst_get_vector(start_node->process_transition_tree, 0);
		apol_vector_t *potential_end_types = apol_vector_create(NULL);
		for (size_t i = 0; i < apol_vector_get_size(proc_trans_rules); i++) {
			avrule_node_t *ptnode = apol_vector_get_element(proc_trans_rules, i);
			apol_vector_append(potential_end_types, (void *)ptnode->type);
		}
		apol_vector_destroy(&proc_trans_rules);
		apol_vector_sort_uniquify(potential_end_types, NULL, NULL);
		//for each end check ep
		for (size_t i = 0; i < apol_vector_get_size(potential_end_types); i++) {
			dummy.type = tmpl_result->end_type = apol_vector_get_element(potential_end_types, i);
			dom_node_t *end_node = NULL;
			apol_bst_get_element(policy->domain_trans_table->domain_table, (void *)&dummy, NULL, (void **)&end_node);
			const qpol_type_t *end_type = dummy.type;
			if (end_type == start_type)
				continue;
			//get all proc trans rules for ths end (may be multiple due to attributes)
			apol_vector_t *ptrules =
				find_avrules_in_node((void *)start_node, APOL_DOMAIN_TRANS_RULE_PROC_TRANS, end_type);
			apol_vector_destroy(&tmpl_result->proc_trans_rules);
			tmpl_result->proc_trans_rules = apol_vector_create(NULL);
			for (size_t j = 0; j < apol_vector_get_size(ptrules); j++) {
				avrule_node_t *pt_ent = apol_vector_get_element(ptrules, j);
				pt_ent->used = true;
				if (apol_vector_append(tmpl_result->proc_trans_rules, (void *)pt_ent->rule)) {
					error = errno;
					apol_vector_destroy(&ptrules);
					apol_vector_destroy(&potential_end_types);
					goto err;
				}
			}
			apol_vector_destroy(&ptrules);
			apol_vector_sort_uniquify(tmpl_result->proc_trans_rules, NULL, NULL);
			if (end_node) {
				//collect potential entrypoint types
				apol_vector_t *eprules = apol_bst_get_vector(end_node->entrypoint_tree, 0);
				apol_vector_t *potential_ep_types = apol_vector_create(NULL);
				if (!eprules || !potential_ep_types) {
					error = errno;
					apol_vector_destroy(&eprules);
					apol_vector_destroy(&potential_end_types);
					goto err;
				}
				for (size_t j = 0; j < apol_vector_get_size(eprules); j++) {
					avrule_node_t *epr = apol_vector_get_element(eprules, j);
					if (apol_vector_append(potential_ep_types, (void *)epr->type)) {
						error = errno;
						apol_vector_destroy(&eprules);
						apol_vector_destroy(&potential_end_types);
						apol_vector_destroy(&potential_ep_types);
						goto err;
					}
				}
				apol_vector_destroy(&eprules);
				apol_vector_sort_uniquify(potential_ep_types, NULL, NULL);
				//for each ep find exec by start
				for (size_t j = 0; j < apol_vector_get_size(potential_ep_types); j++) {
					tmpl_result->ep_type = apol_vector_get_element(potential_ep_types, j);
					ep_node_t edummy =
						{ (const qpol_type_t *)apol_vector_get_element(potential_ep_types, j), NULL, NULL };
					ep_node_t *epnode = NULL;
					apol_bst_get_element(policy->domain_trans_table->entrypoint_table, (void *)&edummy, NULL,
							     (void **)&epnode);
					//get all entrypoint rules for ths end (may be multiple due to attributes)
					apol_vector_destroy(&tmpl_result->ep_rules);
					tmpl_result->ep_rules = apol_vector_create(NULL);
					if (!tmpl_result->ep_rules) {
						error = errno;
						apol_vector_destroy(&potential_end_types);
						apol_vector_destroy(&potential_ep_types);
						goto err;
					}
					eprules = find_avrules_in_node((void *)end_node, APOL_DOMAIN_TRANS_RULE_ENTRYPOINT,
								       tmpl_result->ep_type);
					for (size_t k = 0; k < apol_vector_get_size(eprules); k++) {
						avrule_node_t *ep_ent = apol_vector_get_element(eprules, k);
						ep_ent->used = true;
						if (apol_vector_append(tmpl_result->ep_rules, (void *)ep_ent->rule)) {
							error = errno;
							apol_vector_destroy(&eprules);
							apol_vector_destroy(&potential_end_types);
							apol_vector_destroy(&potential_ep_types);
							goto err;
						}
					}
					apol_vector_destroy(&eprules);
					apol_vector_sort_uniquify(tmpl_result->ep_rules, NULL, NULL);
					if (epnode) {
						//if present find tt
						apol_vector_destroy(&tmpl_result->type_trans_rules);
						tmpl_result->type_trans_rules = apol_vector_create(NULL);
						if (!tmpl_result->type_trans_rules) {
							error = errno;
							apol_vector_destroy(&potential_end_types);
							apol_vector_destroy(&potential_ep_types);
							goto err;
						}
						apol_vector_t *ttrules = find_terules_in_node(epnode, start_type, end_type);
						for (size_t l = 0; l < apol_vector_get_size(ttrules); l++) {
							terule_node_t *tn = apol_vector_get_element(ttrules, l);
							if (apol_vector_append(tmpl_result->type_trans_rules, (void *)tn->rule)) {
								error = errno;
								apol_vector_destroy(&ttrules);
								apol_vector_destroy(&potential_end_types);
								apol_vector_destroy(&potential_ep_types);
								goto err;
							}
						}
						apol_vector_destroy(&ttrules);
						apol_vector_sort_uniquify(tmpl_result->type_trans_rules, NULL, NULL);
						//find execute rules
						apol_vector_destroy(&tmpl_result->exec_rules);
						tmpl_result->exec_rules = apol_vector_create(NULL);
						if (!tmpl_result->exec_rules) {
							error = errno;
							apol_vector_destroy(&potential_end_types);
							apol_vector_destroy(&potential_ep_types);
							goto err;
						}
						apol_vector_t *execrules =
							find_avrules_in_node(epnode, APOL_DOMAIN_TRANS_RULE_EXEC, start_type);
						if (apol_vector_get_size(execrules)) {
							for (size_t l = 0; l < apol_vector_get_size(execrules); l++) {
								avrule_node_t *xnode = apol_vector_get_element(execrules, l);
								//do not mark xnode as used here; it is valid to re-use it.
								if (apol_vector_append
								    (tmpl_result->exec_rules, (void *)xnode->rule)) {
									error = errno;
									apol_vector_destroy(&execrules);
									apol_vector_destroy(&potential_end_types);
									apol_vector_destroy(&potential_ep_types);
									goto err;
								}
							}
							apol_vector_destroy(&execrules);
							apol_vector_sort_uniquify(tmpl_result->exec_rules, NULL, NULL);
							//found everything possible add a result
							apol_domain_trans_result_t *tmp =
								apol_domain_trans_result_create_from_domain_trans_result
								(tmpl_result);
							if (!tmp || apol_vector_append(local_results, (void *)tmp)) {
								error = errno;
								apol_domain_trans_result_destroy(&tmp);
								apol_vector_destroy(&potential_end_types);
								apol_vector_destroy(&potential_ep_types);
								goto err;
							}
							//reset execute rules
							apol_vector_destroy(&tmpl_result->exec_rules);
							tmpl_result->exec_rules = apol_vector_create(NULL);
							if (!tmpl_result->exec_rules) {
								error = errno;
								apol_vector_destroy(&potential_end_types);
								apol_vector_destroy(&potential_ep_types);
								goto err;
							}
							//reset type transition rules
							apol_vector_destroy(&tmpl_result->type_trans_rules);
							tmpl_result->type_trans_rules = apol_vector_create(NULL);
							if (!tmpl_result->type_trans_rules) {
								error = errno;
								apol_vector_destroy(&potential_end_types);
								apol_vector_destroy(&potential_ep_types);
								goto err;
							}
						} else {
							//have proc_trans and entrypoint but no execute
							apol_domain_trans_result_t *tmp =
								apol_domain_trans_result_create_from_domain_trans_result
								(tmpl_result);
							if (!tmp || apol_vector_append(local_results, (void *)tmp)) {
								error = errno;
								apol_domain_trans_result_destroy(&tmp);
								apol_vector_destroy(&potential_end_types);
								apol_vector_destroy(&potential_ep_types);
								goto err;
							}
						}
						apol_vector_destroy(&execrules);
					} else {
						//have proc_trans and entrypoint but no execute
						apol_domain_trans_result_t *tmp =
							apol_domain_trans_result_create_from_domain_trans_result(tmpl_result);
						if (!tmp || apol_vector_append(local_results, (void *)tmp)) {
							error = errno;
							apol_domain_trans_result_destroy(&tmp);
							apol_vector_destroy(&potential_end_types);
							apol_vector_destroy(&potential_ep_types);
							goto err;
						}
					}
					//reset entrypoint rules
					apol_vector_destroy(&tmpl_result->ep_rules);
					tmpl_result->ep_rules = apol_vector_create(NULL);
					if (!tmpl_result->ep_rules) {
						error = errno;
						apol_vector_destroy(&potential_end_types);
						apol_vector_destroy(&potential_ep_types);
						goto err;
					}
				}
				apol_vector_destroy(&potential_ep_types);
			} else {
				//have proc_trans but end has no ep
				apol_domain_trans_result_t *tmp =
					apol_domain_trans_result_create_from_domain_trans_result(tmpl_result);
				if (!tmp || apol_vector_append(local_results, (void *)tmp)) {
					error = errno;
					apol_domain_trans_result_destroy(&tmp);
					goto err;
				}
			}
		}
		apol_vector_destroy(&potential_end_types);
		//validate all
		for (size_t i = 0; i < apol_vector_get_size(local_results); i++) {
			apol_domain_trans_result_t *res = apol_vector_get_element(local_results, i);
			if (res->start_type && res->ep_type && res->end_type && apol_vector_get_size(res->proc_trans_rules) &&
			    apol_vector_get_size(res->ep_rules) && apol_vector_get_size(res->exec_rules) &&
			    (requires_setexec_or_type_trans(policy)
			     ? (apol_vector_get_size(res->setexec_rules) || apol_vector_get_size(res->type_trans_rules)) : true)) {
				res->valid = true;
			}
		}
	}
	//iff looking for invalid find orphan type_transition rules
	if (dta->valid & APOL_DOMAIN_TRANS_SEARCH_INVALID) {
		if (domain_trans_table_find_orphan_type_transitions(policy, dta, local_results)) {
			error = errno;
			goto err;
		}
	}
	apol_domain_trans_result_destroy(&tmpl_result);

	return 0;
      err:
	apol_domain_trans_result_destroy(&tmpl_result);
	errno = error;
	return -1;
}

static int domain_trans_table_get_all_reverse_trans(apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
						    apol_vector_t * local_results, const qpol_type_t * end_type)
{
	int error = 0;
	//create template result this will hold common data for each step and be copied as needed
	apol_domain_trans_result_t *tmpl_result = domain_trans_result_create();
	if (!tmpl_result) {
		error = errno;
		goto err;
	}
	//find end node
	dom_node_t dummy = { end_type, NULL, NULL, NULL };
	dom_node_t *end_node = NULL;
	apol_bst_get_element(policy->domain_trans_table->domain_table, (void *)&dummy, NULL, (void **)&end_node);
	if (end_node) {
		tmpl_result->end_type = end_type;
		//collect potential entrypoint types
		apol_vector_t *eprules = apol_bst_get_vector(end_node->entrypoint_tree, 0);
		apol_vector_t *potential_ep_types = apol_vector_create(NULL);
		if (!eprules || !potential_ep_types) {
			error = errno;
			apol_vector_destroy(&eprules);
			goto err;
		}
		for (size_t j = 0; j < apol_vector_get_size(eprules); j++) {
			avrule_node_t *epr = apol_vector_get_element(eprules, j);
			if (apol_vector_append(potential_ep_types, (void *)epr->type)) {
				error = errno;
				apol_vector_destroy(&eprules);
				apol_vector_destroy(&potential_ep_types);
				goto err;
			}
		}
		apol_vector_destroy(&eprules);
		apol_vector_sort_uniquify(potential_ep_types, NULL, NULL);
		for (size_t i = 0; i < apol_vector_get_size(potential_ep_types); i++) {
			tmpl_result->ep_type = apol_vector_get_element(potential_ep_types, i);
			//get all ep rules for this end (may be multiple due to attributes)
			eprules = find_avrules_in_node((void *)end_node, APOL_DOMAIN_TRANS_RULE_ENTRYPOINT, tmpl_result->ep_type);
			apol_vector_destroy(&tmpl_result->ep_rules);
			tmpl_result->ep_rules = apol_vector_create(NULL);
			for (size_t j = 0; j < apol_vector_get_size(eprules); j++) {
				avrule_node_t *ep_ent = apol_vector_get_element(eprules, j);
				ep_ent->used = true;
				if (apol_vector_append(tmpl_result->ep_rules, (void *)ep_ent->rule)) {
					error = errno;
					apol_vector_destroy(&eprules);
					apol_vector_destroy(&potential_ep_types);
					goto err;
				}
			}
			apol_vector_destroy(&eprules);
			apol_vector_sort_uniquify(tmpl_result->ep_rules, NULL, NULL);
			ep_node_t edummy = { tmpl_result->ep_type, NULL, NULL };
			ep_node_t *epnode = NULL;
			apol_bst_get_element(policy->domain_trans_table->entrypoint_table, (void *)&edummy, NULL, (void **)&epnode);
			//for each ep find exec rules to generate list of potential start types
			if (epnode) {
				apol_vector_t *execrules = apol_bst_get_vector(epnode->execute_tree, 0);
				apol_vector_t *potential_start_types = apol_vector_create(NULL);
				if (!execrules || !potential_start_types) {
					error = errno;
					apol_vector_destroy(&execrules);
					goto err;
				}
				for (size_t k = 0; k < apol_vector_get_size(execrules); k++) {
					avrule_node_t *n = apol_vector_get_element(execrules, k);
					if (apol_vector_append(potential_start_types, (void *)n->type)) {
						error = errno;
						apol_vector_destroy(&execrules);
						apol_vector_destroy(&potential_start_types);
						apol_vector_destroy(&potential_ep_types);
						goto err;
					}
				}
				apol_vector_destroy(&execrules);
				apol_vector_sort_uniquify(potential_start_types, NULL, NULL);
				for (size_t k = 0; k < apol_vector_get_size(potential_start_types); k++) {
					tmpl_result->start_type = apol_vector_get_element(potential_start_types, k);
					//no transition to self
					if (tmpl_result->end_type == tmpl_result->start_type)
						continue;
					//get all execute rule for this start type
					apol_vector_t *exec_rules =
						find_avrules_in_node((void *)epnode, APOL_DOMAIN_TRANS_RULE_EXEC,
								     tmpl_result->start_type);
					apol_vector_destroy(&tmpl_result->exec_rules);
					tmpl_result->exec_rules = apol_vector_create(NULL);
					for (size_t l = 0; l < apol_vector_get_size(exec_rules); l++) {
						avrule_node_t *n = apol_vector_get_element(exec_rules, l);
						n->used = true;
						if (apol_vector_append(tmpl_result->exec_rules, (void *)n->rule)) {
							error = errno;
							apol_vector_destroy(&exec_rules);
							apol_vector_destroy(&potential_start_types);
							apol_vector_destroy(&potential_ep_types);
							goto err;
						}
					}
					apol_vector_destroy(&exec_rules);
					apol_vector_sort_uniquify(tmpl_result->exec_rules, NULL, NULL);
					//check for type transition rules
					apol_vector_t *ttrules =
						find_terules_in_node(epnode, tmpl_result->start_type, tmpl_result->end_type);
					apol_vector_destroy(&tmpl_result->type_trans_rules);
					tmpl_result->type_trans_rules = apol_vector_create(NULL);
					if (!tmpl_result->type_trans_rules) {
						error = errno;
						apol_vector_destroy(&ttrules);
						apol_vector_destroy(&potential_start_types);
						apol_vector_destroy(&potential_ep_types);
						goto err;
					}
					for (size_t l = 0; l < apol_vector_get_size(ttrules); l++) {
						terule_node_t *n = apol_vector_get_element(ttrules, l);
						n->used = true;
						if (apol_vector_append(tmpl_result->type_trans_rules, (void *)n->rule)) {
							error = errno;
							apol_vector_destroy(&ttrules);
							apol_vector_destroy(&potential_start_types);
							apol_vector_destroy(&potential_ep_types);
							goto err;
						}
					}
					apol_vector_destroy(&ttrules);
					apol_vector_sort_uniquify(tmpl_result->type_trans_rules, NULL, NULL);
					dummy.type = tmpl_result->start_type;
					dom_node_t *start_node = NULL;
					apol_bst_get_element(policy->domain_trans_table->domain_table, (void *)&dummy, NULL,
							     (void **)&start_node);
					if (start_node) {
						//for each start check setexec if needed
						if (requires_setexec_or_type_trans(policy)) {
							apol_vector_destroy(&tmpl_result->setexec_rules);
							tmpl_result->setexec_rules = apol_vector_create(NULL);
							if (!tmpl_result->setexec_rules ||
							    apol_vector_cat(tmpl_result->setexec_rules,
									    start_node->setexec_rules)) {
								error = errno;
								apol_vector_destroy(&potential_start_types);
								apol_vector_destroy(&potential_ep_types);
								goto err;
							}
						}
						//for each start find pt
						apol_vector_destroy(&tmpl_result->proc_trans_rules);
						tmpl_result->proc_trans_rules = apol_vector_create(NULL);
						if (!tmpl_result->proc_trans_rules) {
							error = errno;
							apol_vector_destroy(&potential_start_types);
							apol_vector_destroy(&potential_ep_types);
							goto err;
						}
						apol_vector_t *pt_rules = NULL;
						pt_rules =
							find_avrules_in_node(start_node, APOL_DOMAIN_TRANS_RULE_PROC_TRANS,
									     tmpl_result->end_type);
						if (apol_vector_get_size(pt_rules)) {
							for (size_t l = 0; l < apol_vector_get_size(pt_rules); l++) {
								avrule_node_t *n = apol_vector_get_element(pt_rules, l);
								apol_vector_append(tmpl_result->proc_trans_rules, (void *)n->rule);
							}
							apol_vector_destroy(&pt_rules);
							apol_vector_sort_uniquify(tmpl_result->proc_trans_rules, NULL, NULL);
							// have all possible rules add this entry
							apol_domain_trans_result_t *tmp =
								apol_domain_trans_result_create_from_domain_trans_result
								(tmpl_result);
							if (!tmp || apol_vector_append(local_results, (void *)tmp)) {
								error = errno;
								apol_domain_trans_result_destroy(&tmp);
								apol_vector_destroy(&potential_start_types);
								apol_vector_destroy(&potential_ep_types);
								goto err;
							}
							//reset process transition rules
							apol_vector_destroy(&tmpl_result->proc_trans_rules);
							tmpl_result->proc_trans_rules = apol_vector_create(NULL);
							if (!tmpl_result->proc_trans_rules) {
								error = errno;
								apol_vector_destroy(&potential_start_types);
								apol_vector_destroy(&potential_ep_types);
								goto err;
							}
							//reset setexec rules
							apol_vector_destroy(&tmpl_result->setexec_rules);
							tmpl_result->setexec_rules = apol_vector_create(NULL);
							if (!tmpl_result->setexec_rules) {
								error = errno;
								apol_vector_destroy(&potential_start_types);
								apol_vector_destroy(&potential_ep_types);
								goto err;
							}
						} else {
							//have entrypoint and execute rules but no process transition rule
							apol_domain_trans_result_t *tmp =
								apol_domain_trans_result_create_from_domain_trans_result
								(tmpl_result);
							if (!tmp || apol_vector_append(local_results, (void *)tmp)) {
								error = errno;
								apol_domain_trans_result_destroy(&tmp);
								apol_vector_destroy(&potential_start_types);
								apol_vector_destroy(&potential_ep_types);
								apol_vector_destroy(&pt_rules);
								goto err;
							}
						}
						apol_vector_destroy(&pt_rules);
					} else {
						//have entrypoint and execute rules but no process transition rule
						apol_domain_trans_result_t *tmp =
							apol_domain_trans_result_create_from_domain_trans_result(tmpl_result);
						if (!tmp || apol_vector_append(local_results, (void *)tmp)) {
							error = errno;
							apol_domain_trans_result_destroy(&tmp);
							apol_vector_destroy(&potential_start_types);
							apol_vector_destroy(&potential_ep_types);
							goto err;
						}
					}
					//reset execute rules
					apol_vector_destroy(&tmpl_result->exec_rules);
					tmpl_result->exec_rules = apol_vector_create(NULL);
					if (!tmpl_result->exec_rules) {
						error = errno;
						apol_vector_destroy(&potential_start_types);
						apol_vector_destroy(&potential_ep_types);
						goto err;
					}
					//reset type transition rules
					apol_vector_destroy(&tmpl_result->type_trans_rules);
					tmpl_result->type_trans_rules = apol_vector_create(NULL);
					if (!tmpl_result->type_trans_rules) {
						error = errno;
						apol_vector_destroy(&potential_start_types);
						apol_vector_destroy(&potential_ep_types);
						goto err;
					}
				}
				apol_vector_destroy(&potential_start_types);
			} else {
				//have entrypoint but no exec
				apol_domain_trans_result_t *tmp =
					apol_domain_trans_result_create_from_domain_trans_result(tmpl_result);
				if (!tmp || apol_vector_append(local_results, (void *)tmp)) {
					error = errno;
					apol_domain_trans_result_destroy(&tmp);
					goto err;
				}
			}
		}
		apol_vector_destroy(&potential_ep_types);

		//validate all
		for (size_t i = 0; i < apol_vector_get_size(local_results); i++) {
			apol_domain_trans_result_t *res = apol_vector_get_element(local_results, i);
			if (res->start_type && res->ep_type && res->end_type && apol_vector_get_size(res->proc_trans_rules) &&
			    apol_vector_get_size(res->ep_rules) && apol_vector_get_size(res->exec_rules) &&
			    (requires_setexec_or_type_trans(policy)
			     ? (apol_vector_get_size(res->setexec_rules) || apol_vector_get_size(res->type_trans_rules)) : true)) {
				res->valid = true;
			}
		}
	}
	//iff looking for invalid find orphan type_transition rules
	if (dta->valid & APOL_DOMAIN_TRANS_SEARCH_INVALID) {
		if (domain_trans_table_find_orphan_type_transitions(policy, dta, local_results)) {
			error = errno;
			goto err;
		}
	}

	apol_domain_trans_result_destroy(&tmpl_result);
	return 0;

      err:
	apol_domain_trans_result_destroy(&tmpl_result);
	errno = error;
	return -1;
}

int apol_domain_trans_analysis_do(apol_policy_t * policy, apol_domain_trans_analysis_t * dta, apol_vector_t ** results)
{
	apol_vector_t *local_results = NULL;
	apol_avrule_query_t *accessq = NULL;
	int error = 0;
	if (!results)
		*results = NULL;
	if (!policy || !dta || !results) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	/* build table if not already present */
	if (!(policy->domain_trans_table)) {
		if (apol_policy_build_domain_trans_table(policy))
			return -1;     /* errors already reported by build function */
	}

	/* validate analysis options */
	if (dta->direction == 0 || dta->valid & ~(APOL_DOMAIN_TRANS_SEARCH_BOTH) || !(dta->start_type)) {
		error = EINVAL;
		ERR(policy, "%s", strerror(EINVAL));
		goto err;
	}
	size_t num_atypes = apol_vector_get_size(dta->access_types);
	size_t num_aclasses = apol_vector_get_size(dta->access_classes);
	size_t num_aprems = apol_vector_get_size(dta->access_perms);
	if ((num_atypes == 0 && (num_aclasses != 0 || num_aprems != 0)) ||
	    (num_aclasses == 0 && (num_atypes != 0 || num_aprems != 0)) ||
	    (num_aprems == 0 && (num_aclasses != 0 || num_atypes != 0))) {
		error = EINVAL;
		ERR(policy, "%s", strerror(EINVAL));
		goto err;
	}

	/* get starting type */
	const qpol_type_t *start_type = NULL;
	if (qpol_policy_get_type_by_name(policy->p, dta->start_type, &start_type)) {
		error = errno;
		ERR(policy, "Unable to perform analysis: Invalid starting type %s", dta->start_type);
		goto err;
	}
	unsigned char isattr = 0;
	qpol_type_get_isattr(policy->p, start_type, &isattr);
	if (isattr) {
		ERR(policy, "%s", "Attributes are not valid here.");
		error = EINVAL;
		goto err;
	}

	local_results = apol_vector_create(domain_trans_result_free);
	/* get all transitions for the requested direction */
	if (dta->direction == APOL_DOMAIN_TRANS_DIRECTION_REVERSE) {
		if (domain_trans_table_get_all_reverse_trans(policy, dta, local_results, start_type)) {
			error = errno;
			goto err;
		}
	} else {
		if (domain_trans_table_get_all_forward_trans(policy, dta, local_results, start_type)) {
			error = errno;
			goto err;
		}
	}

	/* if requested, filter by validity */
	if (dta->valid != APOL_DOMAIN_TRANS_SEARCH_BOTH) {
		for (size_t i = 0; i < apol_vector_get_size(local_results); /* increment later */ ) {
			apol_domain_trans_result_t *res = apol_vector_get_element(local_results, i);
			if (res->valid != (dta->valid == APOL_DOMAIN_TRANS_SEARCH_VALID)) {
				apol_vector_remove(local_results, i);
				domain_trans_result_free(res);
			} else {
				i++;
			}
		}
	}

	/* if filtering by result type, do that now */
	if (dta->result) {
		for (size_t i = 0; i < apol_vector_get_size(local_results); /* increment later */ ) {
			apol_domain_trans_result_t *res = apol_vector_get_element(local_results, i);
			const qpol_type_t *type = NULL;
			if (dta->direction == APOL_DOMAIN_TRANS_DIRECTION_REVERSE) {
				type = res->start_type;
			} else {
				type = res->end_type;
			}
			int compval = apol_compare_type(policy, type, dta->result, APOL_QUERY_REGEX, &dta->result_regex);
			if (compval < 0) {
				error = errno;
				goto err;
			} else if (compval > 0) {
				i++;
			} else {
				apol_vector_remove(local_results, i);
				domain_trans_result_free(res);
			}
		}
	}

	/* finally do access filtering */
	if (dta->direction == APOL_DOMAIN_TRANS_DIRECTION_FORWARD && num_atypes && num_aclasses && num_aprems) {
		accessq = apol_avrule_query_create();
		apol_avrule_query_set_rules(policy, accessq, QPOL_RULE_ALLOW);
		for (size_t i = 0; i < num_aclasses; i++) {
			if (apol_avrule_query_append_class
			    (policy, accessq, (char *)apol_vector_get_element(dta->access_classes, i))) {
				error = errno;
				goto err;
			}
		}
		for (size_t i = 0; i < num_aprems; i++) {
			if (apol_avrule_query_append_perm(policy, accessq, (char *)apol_vector_get_element(dta->access_perms, i))) {
				error = errno;
				goto err;
			}
		}
		for (size_t i = 0; i < apol_vector_get_size(local_results); /* increment later */ ) {
			const char *end_name = NULL;
			apol_domain_trans_result_t *res = apol_vector_get_element(local_results, i);
			if (qpol_type_get_name(apol_policy_get_qpol(policy), res->end_type, &end_name) ||
			    apol_avrule_query_set_source(policy, accessq, end_name, 1)) {
				error = errno;
				goto err;
			}
			apol_vector_t *tmp_access = apol_vector_create(NULL);
			for (size_t j = 0; j < num_atypes; j++) {
				if (apol_avrule_query_set_target
				    (policy, accessq, (char *)apol_vector_get_element(dta->access_types, j), 1)) {
					error = errno;
					apol_vector_destroy(&tmp_access);
					goto err;
				}
				apol_vector_t *cur_tgt_v = NULL;
				apol_avrule_get_by_query(policy, accessq, &cur_tgt_v);
				apol_vector_cat(tmp_access, cur_tgt_v);
				apol_vector_destroy(&cur_tgt_v);
			}
			if (apol_vector_get_size(tmp_access)) {
				res->access_rules = tmp_access;
				tmp_access = NULL;
				i++;
			} else {
				apol_vector_remove(local_results, i);
				domain_trans_result_free(res);
			}
			apol_vector_destroy(&tmp_access);
		}
		apol_avrule_query_destroy(&accessq);
	}

	*results = apol_vector_create(domain_trans_result_free);
	if (!(*results)) {
		error = errno;
		goto err;
	}
	for (size_t i = 0; i < apol_vector_get_size(local_results); i++) {
		apol_domain_trans_result_t *res =
			apol_domain_trans_result_create_from_domain_trans_result((apol_domain_trans_result_t *)
										 apol_vector_get_element(local_results, i));
		if (!res || apol_vector_append(*results, (void *)res)) {
			error = errno;
			domain_trans_result_free(res);
			goto err;
		}
	}
	apol_vector_destroy(&local_results);

	return 0;
      err:
	apol_vector_destroy(&local_results);
	apol_vector_destroy(results);
	apol_avrule_query_destroy(&accessq);
	errno = error;
	return -1;
}

/* result */

const qpol_type_t *apol_domain_trans_result_get_start_type(const apol_domain_trans_result_t * dtr)
{
	if (dtr) {
		return dtr->start_type;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

const qpol_type_t *apol_domain_trans_result_get_entrypoint_type(const apol_domain_trans_result_t * dtr)
{
	if (dtr) {
		return dtr->ep_type;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

const qpol_type_t *apol_domain_trans_result_get_end_type(const apol_domain_trans_result_t * dtr)
{
	if (dtr) {
		return dtr->end_type;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

const apol_vector_t *apol_domain_trans_result_get_proc_trans_rules(const apol_domain_trans_result_t * dtr)
{
	if (dtr) {
		return dtr->proc_trans_rules;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

const apol_vector_t *apol_domain_trans_result_get_entrypoint_rules(const apol_domain_trans_result_t * dtr)
{
	if (dtr) {
		return dtr->ep_rules;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

const apol_vector_t *apol_domain_trans_result_get_exec_rules(const apol_domain_trans_result_t * dtr)
{
	if (dtr) {
		return dtr->exec_rules;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

const apol_vector_t *apol_domain_trans_result_get_setexec_rules(const apol_domain_trans_result_t * dtr)
{
	if (dtr) {
		return dtr->setexec_rules;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

const apol_vector_t *apol_domain_trans_result_get_type_trans_rules(const apol_domain_trans_result_t * dtr)
{
	if (dtr) {
		return dtr->type_trans_rules;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

int apol_domain_trans_result_is_trans_valid(const apol_domain_trans_result_t * dtr)
{
	if (dtr) {
		return dtr->valid;
	} else {
		errno = EINVAL;
		return 0;
	}
}

const apol_vector_t *apol_domain_trans_result_get_access_rules(const apol_domain_trans_result_t * dtr)
{
	if (dtr) {
		return dtr->access_rules;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

int apol_domain_trans_table_verify_trans(apol_policy_t * policy, const qpol_type_t * start_dom, const qpol_type_t * ep_type,
					 const qpol_type_t * end_dom)
{
	int missing_rules = 0;

	if (!policy || !policy->domain_trans_table) {
		errno = EINVAL;
		return -1;
	}
	//reset the table
	apol_policy_reset_domain_trans_table(policy);
	//find nodes for each type
	dom_node_t start_dummy = { start_dom, NULL, NULL, NULL };
	dom_node_t *start_node = NULL;
	if (start_dom)
		apol_bst_get_element(policy->domain_trans_table->domain_table, (void *)&start_dummy, NULL, (void **)&start_node);
	ep_node_t ep_dummy = { ep_type, NULL, NULL };
	ep_node_t *ep_node = NULL;
	if (ep_type)
		apol_bst_get_element(policy->domain_trans_table->entrypoint_table, (void *)&ep_dummy, NULL, (void **)&ep_node);
	dom_node_t end_dummy = { end_dom, NULL, NULL, NULL };
	dom_node_t *end_node = NULL;
	if (end_dom)
		apol_bst_get_element(policy->domain_trans_table->domain_table, (void *)&end_dummy, NULL, (void **)&end_node);

	bool tt = false, sx = false, ex = false, pt = false, ep = false;

	//find process transition rule
	if (start_node && end_dom) {
		apol_vector_t *v = find_avrules_in_node(start_node, APOL_DOMAIN_TRANS_RULE_PROC_TRANS, end_dom);
		if (apol_vector_get_size(v))
			pt = true;
		apol_vector_destroy(&v);
	}
	//find execute rule
	if (start_dom && ep_node) {
		apol_vector_t *v = find_avrules_in_node(ep_node, APOL_DOMAIN_TRANS_RULE_EXEC, start_dom);
		if (apol_vector_get_size(v))
			ex = true;
		apol_vector_destroy(&v);
	}
	//find entrypoint rules
	if (end_node && ep_type) {
		apol_vector_t *v = find_avrules_in_node(end_node, APOL_DOMAIN_TRANS_RULE_ENTRYPOINT, ep_type);
		if (apol_vector_get_size(v))
			ep = true;
		apol_vector_destroy(&v);
	}
	if (requires_setexec_or_type_trans(policy)) {
		//find setexec rule
		if (start_node)
			if (apol_vector_get_size(start_node->setexec_rules))
				sx = true;
		//find type_transition rule
		if (ep_node && start_dom && end_dom) {
			apol_vector_t *v = find_terules_in_node(ep_node, start_dom, end_dom);
			if (apol_vector_get_size(v)) {
				tt = true;
			}
			apol_vector_destroy(&v);
		}
	} else {
		//old policy version - pretend these exist
		tt = sx = true;
	}

	if (!(pt && ep && ex && (tt || sx))) {
		if (!pt)
			missing_rules |= APOL_DOMAIN_TRANS_RULE_PROC_TRANS;
		if (!ep)
			missing_rules |= APOL_DOMAIN_TRANS_RULE_ENTRYPOINT;
		if (!ex)
			missing_rules |= APOL_DOMAIN_TRANS_RULE_EXEC;
		if (!tt && !sx) {
			missing_rules |= APOL_DOMAIN_TRANS_RULE_SETEXEC;
			//do not report type_transition as missing if there is one for another entrypoint as this would be invalid
			const char *start_name = NULL, *end_name = NULL;
			qpol_type_get_name(apol_policy_get_qpol(policy), start_dom, &start_name);
			qpol_type_get_name(apol_policy_get_qpol(policy), end_dom, &end_name);
			apol_terule_query_t *tq = NULL;
			if (!start_name || !end_name || !(tq = apol_terule_query_create())) {
				return -1;
			}
			apol_terule_query_set_rules(policy, tq, QPOL_RULE_TYPE_TRANS);
			apol_terule_query_set_source(policy, tq, start_name, 1);
			apol_terule_query_set_default(policy, tq, end_name);
			apol_vector_t *v = NULL;
			if (apol_terule_get_by_query(policy, tq, &v)) {
				apol_terule_query_destroy(&tq);
				return -1;
			}
			apol_terule_query_destroy(&tq);
			if (!apol_vector_get_size(v))
				missing_rules |= APOL_DOMAIN_TRANS_RULE_TYPE_TRANS;
			apol_vector_destroy(&v);
		}
	}

	return missing_rules;
}

apol_domain_trans_result_t *apol_domain_trans_result_create_from_domain_trans_result(const apol_domain_trans_result_t * result)
{
	apol_domain_trans_result_t *new_r = NULL;
	int retval = -1;
	if ((new_r = calloc(1, sizeof(*new_r))) == NULL) {
		goto cleanup;
	}
	if (result->proc_trans_rules != NULL &&
	    (new_r->proc_trans_rules = apol_vector_create_from_vector(result->proc_trans_rules, NULL, NULL, NULL)) == NULL) {
		goto cleanup;
	}
	if (result->ep_rules != NULL
	    && (new_r->ep_rules = apol_vector_create_from_vector(result->ep_rules, NULL, NULL, NULL)) == NULL) {
		goto cleanup;
	}
	if (result->exec_rules != NULL
	    && (new_r->exec_rules = apol_vector_create_from_vector(result->exec_rules, NULL, NULL, NULL)) == NULL) {
		goto cleanup;
	}
	if (result->setexec_rules != NULL
	    && (new_r->setexec_rules = apol_vector_create_from_vector(result->setexec_rules, NULL, NULL, NULL)) == NULL) {
		goto cleanup;
	}
	if (result->type_trans_rules != NULL &&
	    (new_r->type_trans_rules = apol_vector_create_from_vector(result->type_trans_rules, NULL, NULL, NULL)) == NULL) {
		goto cleanup;
	}
	if (result->access_rules != NULL
	    && (new_r->access_rules = apol_vector_create_from_vector(result->access_rules, NULL, NULL, NULL)) == NULL) {
		goto cleanup;
	}
	new_r->start_type = result->start_type;
	new_r->ep_type = result->ep_type;
	new_r->end_type = result->end_type;
	new_r->valid = result->valid;
	retval = 0;
      cleanup:
	if (retval != 0) {
		domain_trans_result_free(new_r);
		return NULL;
	}
	return new_r;
}

/******************** protected functions ********************/

void domain_trans_result_free(void *dtr)
{
	apol_domain_trans_result_t *res = (apol_domain_trans_result_t *) dtr;

	if (!res)
		return;

	apol_vector_destroy(&res->proc_trans_rules);
	apol_vector_destroy(&res->ep_rules);
	apol_vector_destroy(&res->exec_rules);
	apol_vector_destroy(&res->setexec_rules);
	apol_vector_destroy(&res->type_trans_rules);
	apol_vector_destroy(&res->access_rules);
	free(res);
}

void apol_domain_trans_result_destroy(apol_domain_trans_result_t ** res)
{
	if (!res || !(*res))
		return;
	domain_trans_result_free((void *)*res);
	*res = NULL;
}
