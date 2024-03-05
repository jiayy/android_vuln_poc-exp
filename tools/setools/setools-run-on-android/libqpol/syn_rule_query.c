/**
 *  @file
 *  Public interface for querying syntactic rules from the extended
 *  policy image.
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

#include <config.h>

#include <qpol/syn_rule_query.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/util.h>
#include <sepol/policydb/conditional.h>
#include "qpol_internal.h"
#include "iterator_internal.h"
#include "syn_rule_internal.h"
#include <errno.h>
#include <stdlib.h>

typedef struct syn_rule_class_state
{
	class_perm_node_t *head;
	class_perm_node_t *cur;
} syn_rule_class_state_t;

static int syn_rule_class_state_end(const qpol_iterator_t * iter)
{
	syn_rule_class_state_t *srcs = NULL;

	if (!iter || !(srcs = (syn_rule_class_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (srcs->cur == NULL)
		return 1;
	else
		return 0;
}

static void *syn_rule_class_state_get_cur(const qpol_iterator_t * iter)
{
	syn_rule_class_state_t *srcs = NULL;
	const policydb_t *db = NULL;

	if (!iter || !(srcs = (syn_rule_class_state_t *) qpol_iterator_state(iter)) ||
	    !(db = qpol_iterator_policy(iter)) || qpol_iterator_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	return db->class_val_to_struct[srcs->cur->tclass - 1];
}

static int syn_rule_class_state_next(qpol_iterator_t * iter)
{
	syn_rule_class_state_t *srcs = NULL;

	if (!iter || !(srcs = (syn_rule_class_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	if (qpol_iterator_end(iter)) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	srcs->cur = srcs->cur->next;

	return STATUS_SUCCESS;
}

static size_t syn_rule_class_state_size(const qpol_iterator_t * iter)
{
	syn_rule_class_state_t *srcs = NULL;
	size_t count = 0;
	class_perm_node_t *cpn = NULL;

	if (!iter || !(srcs = (syn_rule_class_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return 0;
	}

	for (cpn = srcs->head; cpn; cpn = cpn->next)
		count++;

	return count;
}

typedef struct syn_rule_perm_state
{
	char **perm_list;
	size_t perm_list_sz;
	size_t cur;
} syn_rule_perm_state_t;

static int syn_rule_perm_state_end(const qpol_iterator_t * iter)
{
	syn_rule_perm_state_t *srps = NULL;

	if (!iter || !(srps = (syn_rule_perm_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return (srps->cur >= srps->perm_list_sz ? 1 : 0);
}

static void *syn_rule_perm_state_get_cur(const qpol_iterator_t * iter)
{
	syn_rule_perm_state_t *srps = NULL;

	if (!iter || !(srps = (syn_rule_perm_state_t *) qpol_iterator_state(iter)) || qpol_iterator_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	return srps->perm_list[srps->cur];
}

static int syn_rule_perm_state_next(qpol_iterator_t * iter)
{
	syn_rule_perm_state_t *srps = NULL;

	if (!iter || !(srps = (syn_rule_perm_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	if (qpol_iterator_end(iter)) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	srps->cur++;

	return STATUS_SUCCESS;
}

static size_t syn_rule_perm_state_size(const qpol_iterator_t * iter)
{
	syn_rule_perm_state_t *srps = NULL;

	if (!iter || !(srps = (syn_rule_perm_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return srps->perm_list_sz;
}

static void syn_rule_perm_state_free(void *state)
{
	size_t i;

	syn_rule_perm_state_t *srps = (syn_rule_perm_state_t *) state;

	if (!srps)
		return;

	for (i = 0; i < srps->perm_list_sz; i++)
		free(srps->perm_list[i]);
	free(srps->perm_list);
	free(srps);
}

/***************************** type set functions ****************************/

int qpol_type_set_get_included_types_iter(const qpol_policy_t * policy, const qpol_type_set_t * ts, qpol_iterator_t ** iter)
{
	type_set_t *internal_ts = NULL;
	ebitmap_state_t *es = NULL;
	int error = 0;

	if (iter)
		*iter = NULL;

	if (!policy || !ts || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		error = EINVAL;
		return STATUS_ERR;
	}

	internal_ts = (type_set_t *) ts;

	es = calloc(1, sizeof(ebitmap_state_t));
	if (!es) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		errno = error;
		return STATUS_ERR;
	}

	es->bmap = &(internal_ts->types);
	es->cur = es->bmap->node ? es->bmap->node->startbit : 0;

	if (qpol_iterator_create(policy, es, ebitmap_state_get_cur_type,
				 ebitmap_state_next, ebitmap_state_end, ebitmap_state_size, free, iter)) {
		free(es);
		return STATUS_ERR;
	}

	if (es->bmap->node && !ebitmap_get_bit(es->bmap, es->cur))
		ebitmap_state_next(*iter);

	return STATUS_SUCCESS;
}

int qpol_type_set_get_subtracted_types_iter(const qpol_policy_t * policy, const qpol_type_set_t * ts, qpol_iterator_t ** iter)
{
	type_set_t *internal_ts = NULL;
	ebitmap_state_t *es = NULL;
	int error = 0;

	if (iter)
		*iter = NULL;

	if (!policy || !ts || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		error = EINVAL;
		return STATUS_ERR;
	}

	internal_ts = (type_set_t *) ts;

	es = calloc(1, sizeof(ebitmap_state_t));
	if (!es) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		errno = error;
		return STATUS_ERR;
	}

	es->bmap = &(internal_ts->negset);
	es->cur = es->bmap->node ? es->bmap->node->startbit : 0;

	if (qpol_iterator_create(policy, es, ebitmap_state_get_cur_type,
				 ebitmap_state_next, ebitmap_state_end, ebitmap_state_size, free, iter)) {
		free(es);
		return STATUS_ERR;
	}

	if (es->bmap->node && !ebitmap_get_bit(es->bmap, es->cur))
		ebitmap_state_next(*iter);

	return STATUS_SUCCESS;
}

int qpol_type_set_get_is_star(const qpol_policy_t * policy, const qpol_type_set_t * ts, uint32_t * is_star)
{
	type_set_t *internal_ts = NULL;

	if (is_star)
		*is_star = 0;

	if (!policy || !ts || !is_star) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ts = (type_set_t *) ts;

	if (internal_ts->flags == TYPE_STAR)
		*is_star = 1;

	return STATUS_SUCCESS;
}

int qpol_type_set_get_is_comp(const qpol_policy_t * policy, const qpol_type_set_t * ts, uint32_t * is_comp)
{
	type_set_t *internal_ts = NULL;

	if (is_comp)
		*is_comp = 0;

	if (!policy || !ts || !is_comp) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ts = (type_set_t *) ts;

	if (internal_ts->flags == TYPE_COMP)
		*is_comp = 1;

	return STATUS_SUCCESS;
}

/***************************** syn_avule functions ****************************/

int qpol_syn_avrule_get_rule_type(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule, uint32_t * rule_type)
{
	avrule_t *internal_rule = NULL;

	if (rule_type)
		*rule_type = 0;

	if (!policy || !rule || !rule_type) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_rule = ((struct qpol_syn_rule *)rule)->rule;

	if (internal_rule->specified == AVRULE_DONTAUDIT)
		*rule_type = QPOL_RULE_DONTAUDIT;
	else
		*rule_type = internal_rule->specified;

	return STATUS_SUCCESS;
}

int qpol_syn_avrule_get_source_type_set(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule,
					const qpol_type_set_t ** source_set)
{
	avrule_t *internal_rule = NULL;

	if (source_set)
		*source_set = NULL;

	if (!policy || !rule || !source_set) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_rule = ((struct qpol_syn_rule *)rule)->rule;

	*source_set = (qpol_type_set_t *) (&internal_rule->stypes);

	return STATUS_SUCCESS;
}

int qpol_syn_avrule_get_target_type_set(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule,
					const qpol_type_set_t ** target_set)
{
	avrule_t *internal_rule = NULL;

	if (target_set)
		*target_set = NULL;

	if (!policy || !rule || !target_set) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_rule = ((struct qpol_syn_rule *)rule)->rule;

	*target_set = (qpol_type_set_t *) (&internal_rule->ttypes);

	return STATUS_SUCCESS;
}

int qpol_syn_avrule_get_is_target_self(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule, uint32_t * is_self)
{
	avrule_t *internal_rule = NULL;

	if (is_self)
		*is_self = 0;

	if (!policy || !rule || !is_self) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_rule = ((struct qpol_syn_rule *)rule)->rule;

	if (internal_rule->flags & RULE_SELF)
		*is_self = 1;

	return STATUS_SUCCESS;
}

int qpol_syn_avrule_get_class_iter(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule, qpol_iterator_t ** classes)
{
	syn_rule_class_state_t *srcs = NULL;
	avrule_t *internal_rule = NULL;
	int error = 0;

	if (classes)
		*classes = NULL;

	if (!policy || !rule || !classes) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (!(srcs = calloc(1, sizeof(syn_rule_class_state_t)))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		errno = error;
		return STATUS_ERR;
	}

	internal_rule = ((struct qpol_syn_rule *)rule)->rule;
	srcs->head = srcs->cur = internal_rule->perms;

	if (qpol_iterator_create(policy, (void *)srcs,
				 syn_rule_class_state_get_cur, syn_rule_class_state_next,
				 syn_rule_class_state_end, syn_rule_class_state_size, free, classes)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		free(srcs);
		errno = error;
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_syn_avrule_get_perm_iter(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule, qpol_iterator_t ** perms)
{
	avrule_t *internal_rule = NULL;
	policydb_t *db = NULL;
	char **perm_list, *tmp = NULL, **tmp_copy = NULL;
	class_perm_node_t *node = NULL;
	size_t node_num = 0, i, cur, perm_list_sz = 0;
	int error = 0;
	syn_rule_perm_state_t *srps = NULL;

	if (perms)
		*perms = NULL;

	if (!policy || !rule || !perms) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_rule = ((struct qpol_syn_rule *)rule)->rule;
	for (node = internal_rule->perms; node; node = node->next)
		node_num++;

	/* for now allocate space for maximum number of unique perms */
	perm_list = calloc(node_num * 32, sizeof(char *));
	if (!perm_list) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		errno = error;
		return STATUS_ERR;
	}

	for (node = internal_rule->perms; node; node = node->next) {
		for (i = 0; i < db->class_val_to_struct[node->tclass - 1]->permissions.nprim; i++) {
			if (!(node->data & (1 << i)))
				continue;
			tmp = sepol_av_to_string(db, node->tclass, (sepol_access_vector_t) (1 << i));
			if (tmp) {
				tmp++; /* remove prepended space */
				for (cur = 0; cur < perm_list_sz; cur++)
					if (!strcmp(tmp, perm_list[cur]))
						break;
				if (cur < perm_list_sz)
					continue;
				perm_list[perm_list_sz] = strdup(tmp);
				if (!(perm_list[perm_list_sz])) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto err;
				}
				perm_list_sz++;
			} else {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto err;
			}
		}
	}

	/* shrink to actual needed size */
	tmp_copy = realloc(perm_list, perm_list_sz * sizeof(char *));
	if (!tmp_copy) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	perm_list = tmp_copy;

	srps = calloc(1, sizeof(syn_rule_perm_state_t));
	if (!srps) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	srps->perm_list = perm_list;
	srps->perm_list_sz = perm_list_sz;
	srps->cur = 0;

	if (qpol_iterator_create(policy, (void *)srps,
				 syn_rule_perm_state_get_cur, syn_rule_perm_state_next,
				 syn_rule_perm_state_end, syn_rule_perm_state_size, syn_rule_perm_state_free, perms)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	return STATUS_SUCCESS;

      err:
	for (i = 0; i < perm_list_sz; i++)
		free(perm_list[i]);
	free(perm_list);
	errno = error;
	return STATUS_ERR;
}

int qpol_syn_avrule_get_lineno(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule, unsigned long *lineno)
{
	avrule_t *internal_rule = NULL;

	if (lineno)
		*lineno = 0;

	if (!policy || !rule || !lineno) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_rule = ((struct qpol_syn_rule *)rule)->rule;

	*lineno = internal_rule->line;

	return STATUS_SUCCESS;
}

int qpol_syn_avrule_get_cond(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule, const qpol_cond_t ** cond)
{
	if (cond)
		*cond = NULL;

	if (!policy || !rule || !cond) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*cond = (qpol_cond_t *) ((struct qpol_syn_rule *)rule)->cond;
	return STATUS_SUCCESS;
}

int qpol_syn_avrule_get_is_enabled(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule, uint32_t * is_enabled)
{
	int truth;
	if (is_enabled)
		*is_enabled = 0;

	if (!policy || !rule || !is_enabled) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (!((struct qpol_syn_rule *)rule)->cond)
		*is_enabled = 1;
	else {
		truth = cond_evaluate_expr(&policy->p->p, ((struct qpol_syn_rule *)rule)->cond->expr);
		if (truth < 0) {
			ERR(policy, "%s", strerror(ERANGE));
			errno = ERANGE;
			return STATUS_ERR;
		}
		if (!((struct qpol_syn_rule *)rule)->cond_branch)
			*is_enabled = truth;
		else
			*is_enabled = truth ? 0 : 1;
	}
	return STATUS_SUCCESS;
}

/***************************** syn_terule functions ****************************/

int qpol_syn_terule_get_rule_type(const qpol_policy_t * policy, const qpol_syn_terule_t * rule, uint32_t * rule_type)
{
	avrule_t *internal_rule = NULL;

	if (rule_type)
		*rule_type = 0;

	if (!policy || !rule || !rule_type) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_rule = ((struct qpol_syn_rule *)rule)->rule;

	*rule_type = internal_rule->specified;

	return STATUS_SUCCESS;
}

int qpol_syn_terule_get_source_type_set(const qpol_policy_t * policy, const qpol_syn_terule_t * rule,
					const qpol_type_set_t ** source_set)
{
	avrule_t *internal_rule = NULL;

	if (source_set)
		*source_set = NULL;

	if (!policy || !rule || !source_set) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_rule = ((struct qpol_syn_rule *)rule)->rule;

	*source_set = (qpol_type_set_t *) (&internal_rule->stypes);

	return STATUS_SUCCESS;
}

int qpol_syn_terule_get_target_type_set(const qpol_policy_t * policy, const qpol_syn_terule_t * rule,
					const qpol_type_set_t ** target_set)
{
	avrule_t *internal_rule = NULL;

	if (target_set)
		*target_set = NULL;

	if (!policy || !rule || !target_set) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_rule = ((struct qpol_syn_rule *)rule)->rule;

	*target_set = (qpol_type_set_t *) (&internal_rule->ttypes);

	return STATUS_SUCCESS;
}

int qpol_syn_terule_get_class_iter(const qpol_policy_t * policy, const qpol_syn_terule_t * rule, qpol_iterator_t ** classes)
{
	syn_rule_class_state_t *srcs = NULL;
	avrule_t *internal_rule = NULL;
	int error = 0;

	if (classes)
		*classes = NULL;

	if (!policy || !rule || !classes) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (!(srcs = calloc(1, sizeof(syn_rule_class_state_t)))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		errno = error;
		return STATUS_ERR;
	}

	internal_rule = ((struct qpol_syn_rule *)rule)->rule;
	srcs->head = srcs->cur = internal_rule->perms;

	if (qpol_iterator_create(policy, (void *)srcs,
				 syn_rule_class_state_get_cur, syn_rule_class_state_next,
				 syn_rule_class_state_end, syn_rule_class_state_size, free, classes)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		free(srcs);
		errno = error;
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_syn_terule_get_default_type(const qpol_policy_t * policy, const qpol_syn_terule_t * rule, const qpol_type_t ** dflt)
{
	avrule_t *internal_rule = NULL;
	policydb_t *db = NULL;

	if (dflt)
		*dflt = 0;

	if (!policy || !rule || !dflt) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_rule = ((struct qpol_syn_rule *)rule)->rule;
	db = &policy->p->p;

	/* since it is required that default be the same for all classes just return the first */
	*dflt = (qpol_type_t *) (db->type_val_to_struct[internal_rule->perms->data - 1]);

	return STATUS_SUCCESS;
}

int qpol_syn_terule_get_lineno(const qpol_policy_t * policy, const qpol_syn_terule_t * rule, unsigned long *lineno)
{
	avrule_t *internal_rule = NULL;

	if (lineno)
		*lineno = 0;

	if (!policy || !rule || !lineno) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_rule = ((struct qpol_syn_rule *)rule)->rule;

	*lineno = internal_rule->line;

	return STATUS_SUCCESS;
}

int qpol_syn_terule_get_cond(const qpol_policy_t * policy, const qpol_syn_terule_t * rule, const qpol_cond_t ** cond)
{
	if (cond)
		*cond = NULL;

	if (!policy || !rule || !cond) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*cond = (qpol_cond_t *) ((struct qpol_syn_rule *)rule)->cond;
	return STATUS_SUCCESS;
}

int qpol_syn_terule_get_is_enabled(const qpol_policy_t * policy, const qpol_syn_terule_t * rule, uint32_t * is_enabled)
{
	int truth;
	if (is_enabled)
		*is_enabled = 0;

	if (!policy || !rule || !is_enabled) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (!((struct qpol_syn_rule *)rule)->cond)
		*is_enabled = 1;
	else {
		truth = cond_evaluate_expr(&policy->p->p, ((struct qpol_syn_rule *)rule)->cond->expr);
		if (truth < 0) {
			ERR(policy, "%s", strerror(ERANGE));
			errno = ERANGE;
			return STATUS_ERR;
		}
		if (!((struct qpol_syn_rule *)rule)->cond_branch)
			*is_enabled = truth;
		else
			*is_enabled = truth ? 0 : 1;
	}
	return STATUS_SUCCESS;
}
