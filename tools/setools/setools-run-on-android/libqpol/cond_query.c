/**
 * @file
 * Implememtation for the public interface for searching and iterating
 * conditionals
 *
 * @author Kevin Carr kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang jtang@tresys.com
 *
 * Copyright (C) 2006-2007 Tresys Technology, LLC
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

#include <qpol/policy.h>
#include <qpol/cond_query.h>
#include <qpol/bool_query.h>
#include <qpol/avrule_query.h>
#include <qpol/terule_query.h>
#include <qpol/iterator.h>
#include "iterator_internal.h"
#include "qpol_internal.h"

#include <sepol/policydb/conditional.h>

#include <stdlib.h>
#include <errno.h>

typedef struct cond_state
{
	cond_node_t *head;
	cond_node_t *cur;
} cond_state_t;

static int cond_state_end(const qpol_iterator_t * iter)
{
	cond_state_t *cs = NULL;

	if (!iter || !(cs = (cond_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return cs->cur ? 0 : 1;
}

static void *cond_state_get_cur(const qpol_iterator_t * iter)
{
	cond_state_t *cs = NULL;

	if (!iter || !(cs = (cond_state_t *) qpol_iterator_state(iter)) || qpol_iterator_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	return cs->cur;
}

static int cond_state_next(qpol_iterator_t * iter)
{
	cond_state_t *cs = NULL;

	if (!iter || !(cs = (cond_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (qpol_iterator_end(iter)) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	cs->cur = cs->cur->next;

	return STATUS_SUCCESS;
}

static size_t cond_state_size(const qpol_iterator_t * iter)
{
	cond_state_t *cs = NULL;
	cond_node_t *tmp = NULL;
	size_t count = 0;

	if (!iter || !(cs = (cond_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return 0;
	}

	for (tmp = cs->head; tmp; tmp = tmp->next)
		count++;

	return count;
}

int qpol_policy_get_cond_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
{
	int error = 0;
	cond_state_t *cs = NULL;
	policydb_t *db = NULL;

	if (iter)
		*iter = NULL;

	if (!policy || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (!qpol_policy_has_capability(policy, QPOL_CAP_RULES_LOADED)) {
		ERR(policy, "%s", "Cannot get conditionals: Rules not loaded");
		errno = ENOTSUP;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	if (!(cs = calloc(1, sizeof(cond_state_t)))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	cs->head = cs->cur = db->cond_list;

	if (qpol_iterator_create(policy, (void *)cs,
				 cond_state_get_cur, cond_state_next, cond_state_end, cond_state_size, free, iter)) {
		error = errno;
		goto err;
	}

	return STATUS_SUCCESS;

      err:
	free(cs);
	errno = error;
	return STATUS_ERR;
}

typedef struct cond_expr_state
{
	cond_expr_t *head;
	cond_expr_t *cur;
} cond_expr_state_t;

static int cond_expr_state_end(const qpol_iterator_t * iter)
{
	cond_expr_state_t *ces = NULL;

	if (!iter || !(ces = (cond_expr_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return ces->cur ? 0 : 1;
}

static void *cond_expr_state_get_cur(const qpol_iterator_t * iter)
{
	cond_expr_state_t *ces = NULL;

	if (!iter || !(ces = (cond_expr_state_t *) qpol_iterator_state(iter)) || qpol_iterator_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	return ces->cur;
}

static int cond_expr_state_next(qpol_iterator_t * iter)
{
	cond_expr_state_t *ces = NULL;

	if (!iter || !(ces = (cond_expr_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (qpol_iterator_end(iter)) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	ces->cur = ces->cur->next;

	return STATUS_SUCCESS;
}

static size_t cond_expr_state_size(const qpol_iterator_t * iter)
{
	cond_expr_state_t *ces = NULL;
	cond_expr_t *tmp = NULL;
	size_t count = 0;

	if (!iter || !(ces = (cond_expr_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return 0;
	}

	for (tmp = ces->head; tmp; tmp = tmp->next)
		count++;

	return count;
}

int qpol_cond_get_expr_node_iter(const qpol_policy_t * policy, const qpol_cond_t * cond, qpol_iterator_t ** iter)
{
	int error = 0;
	cond_expr_state_t *ces = NULL;
	cond_node_t *internal_cond = NULL;
	policydb_t *db = NULL;

	if (iter)
		*iter = NULL;

	if (!policy || !cond || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_cond = (cond_node_t *) cond;

	if (!(ces = calloc(1, sizeof(cond_expr_state_t)))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	ces->head = ces->cur = internal_cond->expr;

	if (qpol_iterator_create(policy, (void *)ces,
				 cond_expr_state_get_cur, cond_expr_state_next, cond_expr_state_end,
				 cond_expr_state_size, free, iter)) {
		error = errno;
		goto err;
	}

	return STATUS_SUCCESS;

      err:
	free(ces);
	errno = error;
	return STATUS_ERR;
}

typedef struct cond_rule_state
{
	cond_av_list_t *head;
	cond_av_list_t *cur;
	uint32_t rule_type_mask;
} cond_rule_state_t;

static int cond_rule_state_end(const qpol_iterator_t * iter)
{
	cond_rule_state_t *crs = NULL;

	if (!iter || !(crs = (cond_rule_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return crs->cur ? 0 : 1;
}

static void *cond_rule_state_get_cur(const qpol_iterator_t * iter)
{
	cond_rule_state_t *crs = NULL;

	if (!iter || !(crs = (cond_rule_state_t *) qpol_iterator_state(iter)) || qpol_iterator_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	return crs->cur->node;
}

static int cond_rule_state_next(qpol_iterator_t * iter)
{
	cond_rule_state_t *crs = NULL;

	if (!iter || !(crs = (cond_rule_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (qpol_iterator_end(iter)) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	do {
		crs->cur = crs->cur->next;
	} while (crs->cur && !(crs->cur->node->key.specified & crs->rule_type_mask));

	return STATUS_SUCCESS;
}

static size_t cond_rule_state_size(const qpol_iterator_t * iter)
{
	cond_rule_state_t *crs = NULL;
	cond_av_list_t *tmp = NULL;
	size_t count = 0;

	if (!iter || !(crs = (cond_rule_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return 0;
	}

	for (tmp = crs->head; tmp; tmp = tmp->next) {
		if (tmp->node->key.specified & crs->rule_type_mask)
			count++;
	}

	return count;
}

int qpol_cond_get_av_true_iter(const qpol_policy_t * policy, const qpol_cond_t * cond, uint32_t rule_type_mask,
			       qpol_iterator_t ** iter)
{
	int error = 0;
	cond_rule_state_t *crs = NULL;
	cond_node_t *internal_cond = NULL;
	policydb_t *db = NULL;

	if (iter)
		*iter = NULL;

	if (!policy || !cond || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (rule_type_mask & ~(QPOL_RULE_ALLOW | QPOL_RULE_NEVERALLOW | QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT)) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_cond = (cond_node_t *) cond;

	if (!(crs = calloc(1, sizeof(cond_rule_state_t)))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	crs->head = crs->cur = internal_cond->true_list;
	crs->rule_type_mask = rule_type_mask;

	if (qpol_iterator_create(policy, (void *)crs,
				 cond_rule_state_get_cur, cond_rule_state_next, cond_rule_state_end,
				 cond_rule_state_size, free, iter)) {
		error = errno;
		goto err;
	}

	if (crs->cur && !(crs->cur->node->key.specified & crs->rule_type_mask))
		qpol_iterator_next(*iter);

	return STATUS_SUCCESS;

      err:
	free(crs);
	errno = error;
	return STATUS_ERR;
}

int qpol_cond_get_te_true_iter(const qpol_policy_t * policy, const qpol_cond_t * cond, uint32_t rule_type_mask,
			       qpol_iterator_t ** iter)
{
	int error = 0;
	cond_rule_state_t *crs = NULL;
	cond_node_t *internal_cond = NULL;
	policydb_t *db = NULL;

	if (iter)
		*iter = NULL;

	if (!policy || !cond || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (rule_type_mask & ~(QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER)) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_cond = (cond_node_t *) cond;

	if (!(crs = calloc(1, sizeof(cond_rule_state_t)))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	crs->head = crs->cur = internal_cond->true_list;
	crs->rule_type_mask = rule_type_mask;

	if (qpol_iterator_create(policy, (void *)crs,
				 cond_rule_state_get_cur, cond_rule_state_next, cond_rule_state_end,
				 cond_rule_state_size, free, iter)) {
		error = errno;
		goto err;
	}

	if (crs->cur && !(crs->cur->node->key.specified & crs->rule_type_mask))
		qpol_iterator_next(*iter);

	return STATUS_SUCCESS;

      err:
	free(crs);
	errno = error;
	return STATUS_ERR;
}

int qpol_cond_get_av_false_iter(const qpol_policy_t * policy, const qpol_cond_t * cond, uint32_t rule_type_mask,
				qpol_iterator_t ** iter)
{
	int error = 0;
	cond_rule_state_t *crs = NULL;
	cond_node_t *internal_cond = NULL;
	policydb_t *db = NULL;

	if (iter)
		*iter = NULL;

	if (!policy || !cond || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (rule_type_mask & ~(QPOL_RULE_ALLOW | QPOL_RULE_NEVERALLOW | QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT)) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_cond = (cond_node_t *) cond;

	if (!(crs = calloc(1, sizeof(cond_rule_state_t)))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	crs->head = crs->cur = internal_cond->false_list;
	crs->rule_type_mask = rule_type_mask;

	if (qpol_iterator_create(policy, (void *)crs,
				 cond_rule_state_get_cur, cond_rule_state_next, cond_rule_state_end,
				 cond_rule_state_size, free, iter)) {
		error = errno;
		goto err;
	}

	if (crs->cur && !(crs->cur->node->key.specified & crs->rule_type_mask))
		qpol_iterator_next(*iter);

	return STATUS_SUCCESS;

      err:
	free(crs);
	errno = error;
	return STATUS_ERR;
}

int qpol_cond_get_te_false_iter(const qpol_policy_t * policy, const qpol_cond_t * cond, uint32_t rule_type_mask,
				qpol_iterator_t ** iter)
{
	int error = 0;
	cond_rule_state_t *crs = NULL;
	cond_node_t *internal_cond = NULL;
	policydb_t *db = NULL;

	if (iter)
		*iter = NULL;

	if (!policy || !cond || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (rule_type_mask & ~(QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER)) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_cond = (cond_node_t *) cond;

	if (!(crs = calloc(1, sizeof(cond_rule_state_t)))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	crs->head = crs->cur = internal_cond->false_list;
	crs->rule_type_mask = rule_type_mask;

	if (qpol_iterator_create(policy, (void *)crs,
				 cond_rule_state_get_cur, cond_rule_state_next, cond_rule_state_end,
				 cond_rule_state_size, free, iter)) {
		error = errno;
		goto err;
	}

	if (crs->cur && !(crs->cur->node->key.specified & crs->rule_type_mask))
		qpol_iterator_next(*iter);

	return STATUS_SUCCESS;

      err:
	free(crs);
	errno = error;
	return STATUS_ERR;
}

int qpol_cond_eval(const qpol_policy_t * policy, const qpol_cond_t * cond, uint32_t * is_true)
{
	int error = 0;
	cond_node_t *internal_cond = NULL;

	if (is_true)
		*is_true = 0;

	if (!policy || !cond || !is_true) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_cond = (cond_node_t *) cond;

	if ((*is_true = (uint32_t) cond_evaluate_expr(&policy->p->p, internal_cond->expr)) > 1) {
		error = ERANGE;
		goto err;
	}

	return STATUS_SUCCESS;

      err:
	ERR(policy, "%s", strerror(error));
	errno = error;
	return STATUS_ERR;
}

int qpol_cond_expr_node_get_expr_type(const qpol_policy_t * policy, const qpol_cond_expr_node_t * node, uint32_t * expr_type)
{
	cond_expr_t *internal_cond = NULL;

	if (expr_type)
		*expr_type = 0;

	if (!policy || !node || !expr_type) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_cond = (cond_expr_t *) node;

	*expr_type = internal_cond->expr_type;

	return STATUS_SUCCESS;
}

int qpol_cond_expr_node_get_bool(const qpol_policy_t * policy, const qpol_cond_expr_node_t * node, qpol_bool_t ** cond_bool)
{
	int error = 0;
	cond_expr_t *internal_cond = NULL;
	policydb_t *db = NULL;

	if (cond_bool)
		*cond_bool = NULL;

	if (!policy || !node || !cond_bool) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_cond = (cond_expr_t *) node;

	if (internal_cond->expr_type != QPOL_COND_EXPR_BOOL) {
		error = EINVAL;
		goto err;
	}

	if (!(*cond_bool = (qpol_bool_t *) db->bool_val_to_struct[internal_cond->bool - 1])) {
		error = EINVAL;
		goto err;
	}

	return STATUS_SUCCESS;

      err:
	ERR(policy, "%s", strerror(error));
	errno = error;
	return STATUS_ERR;
}
