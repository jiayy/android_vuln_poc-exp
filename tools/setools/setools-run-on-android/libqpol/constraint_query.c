/**
 * @file
 * Implementation of the public interface for searching and iterating over
 * constraints
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

#include <config.h>

#include <qpol/policy.h>
#include <qpol/constraint_query.h>
#include <qpol/iterator.h>
#include <qpol/class_perm_query.h>
#include "qpol_internal.h"
#include "iterator_internal.h"

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/constraint.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct qpol_constraint
{
	const qpol_class_t *obj_class;
	constraint_node_t *constr;
};

typedef struct policy_constr_state
{
	qpol_iterator_t *class_iter;
	qpol_iterator_t *constr_iter;
	const qpol_policy_t *policy;   /* needed to get sub iterators */
} policy_constr_state_t;

static int policy_constr_state_end(const qpol_iterator_t * iter)
{
	policy_constr_state_t *pcs = NULL;

	if (!iter || !(pcs = (policy_constr_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return (qpol_iterator_end(pcs->class_iter) && qpol_iterator_end(pcs->constr_iter)) ? 1 : 0;
}

static void *policy_constr_state_get_cur(const qpol_iterator_t * iter)
{
	policy_constr_state_t *pcs = NULL;
	void *tmp = NULL;

	if (!iter || !(pcs = (policy_constr_state_t *) qpol_iterator_state(iter)) || qpol_iterator_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	if (qpol_iterator_get_item(pcs->constr_iter, &tmp)) {
		return NULL;
	}

	return tmp;
}

static int policy_constr_state_next(qpol_iterator_t * iter)
{
	policy_constr_state_t *pcs = NULL;
	qpol_class_t *obj_class = NULL;

	if (!iter || !(pcs = (policy_constr_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (qpol_iterator_end(iter)) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	qpol_iterator_next(pcs->constr_iter);
	while (qpol_iterator_end(pcs->constr_iter)) {
		qpol_iterator_destroy(&pcs->constr_iter);
		qpol_iterator_next(pcs->class_iter);
		if (qpol_iterator_end(pcs->class_iter))
			return STATUS_SUCCESS;
		if (qpol_iterator_get_item(pcs->class_iter, (void **)&obj_class))
			return STATUS_ERR;
		if (qpol_class_get_constraint_iter(pcs->policy, obj_class, &pcs->constr_iter))
			return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

static size_t policy_constr_state_size(const qpol_iterator_t * iter)
{
	policy_constr_state_t *pcs = NULL;
	qpol_class_t *obj_class = NULL;
	qpol_iterator_t *internal_iter = NULL, *constr_iter = NULL;
	size_t count = 0, tmp = 0;

	if (!iter || !(pcs = (policy_constr_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return 0;
	}

	if (qpol_policy_get_class_iter(pcs->policy, &internal_iter))
		return 0;

	for (; !qpol_iterator_end(internal_iter); qpol_iterator_next(internal_iter)) {
		if (qpol_iterator_get_item(internal_iter, (void **)&obj_class))
			goto err;
		if (qpol_class_get_constraint_iter(pcs->policy, obj_class, &constr_iter))
			goto err;
		if (qpol_iterator_get_size(constr_iter, &tmp))
			goto err;
		count += tmp;
		tmp = 0;
		qpol_iterator_destroy(&constr_iter);
	}

	qpol_iterator_destroy(&internal_iter);
	return count;

      err:
	qpol_iterator_destroy(&internal_iter);
	qpol_iterator_destroy(&constr_iter);
	return 0;
}

static void policy_constr_state_free(void *x)
{
	policy_constr_state_t *pcs = (policy_constr_state_t *) x;

	if (!pcs)
		return;

	qpol_iterator_destroy(&pcs->class_iter);
	qpol_iterator_destroy(&pcs->constr_iter);
	free(pcs);
}

int qpol_policy_get_constraint_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
{
	policy_constr_state_t *pcs = NULL;
	int error = 0;
	qpol_class_t *tmp = NULL;

	if (iter)
		*iter = NULL;

	if (!policy || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (!(pcs = calloc(1, sizeof(policy_constr_state_t)))) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return STATUS_ERR;
	}
	pcs->policy = policy;
	if (qpol_policy_get_class_iter(policy, &pcs->class_iter)) {
		error = errno;
		goto err;
	}
	if (qpol_iterator_get_item(pcs->class_iter, (void **)&tmp)) {
		error = errno;
		ERR(policy, "Error getting first class: %s", strerror(error));
		goto err;
	}
	if (qpol_class_get_constraint_iter(policy, tmp, &pcs->constr_iter)) {
		error = errno;
		goto err;
	}

	if (qpol_iterator_create(policy, (void *)pcs,
				 policy_constr_state_get_cur, policy_constr_state_next,
				 policy_constr_state_end, policy_constr_state_size, policy_constr_state_free, iter)) {
		error = errno;
		goto err;
	}

	if (qpol_iterator_end(pcs->constr_iter)) {
		if (qpol_iterator_next(*iter)) {
			error = errno;
			pcs = NULL;    /* avoid double free, iterator will destroy this */
			ERR(policy, "Error finding first constraint: %s", strerror(error));
			goto err;
		}
	}

	return STATUS_SUCCESS;

      err:
	policy_constr_state_free(pcs);
	qpol_iterator_destroy(iter);
	errno = error;
	return STATUS_ERR;
}

int qpol_constraint_get_class(const qpol_policy_t * policy, const qpol_constraint_t * constr, const qpol_class_t ** obj_class)
{
	if (obj_class)
		*obj_class = NULL;

	if (!policy || !constr || !obj_class) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*obj_class = constr->obj_class;

	return STATUS_SUCCESS;
}

int qpol_constraint_get_perm_iter(const qpol_policy_t * policy, const qpol_constraint_t * constr, qpol_iterator_t ** iter)
{
	perm_state_t *ps = NULL;
	constraint_node_t *internal_constr = NULL;

	if (iter)
		*iter = NULL;

	if (!policy || !constr || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_constr = (constraint_node_t *) constr->constr;

	if (!(ps = calloc(1, sizeof(perm_state_t)))) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
	}
	ps->perm_set = internal_constr->permissions;
	qpol_class_get_value(policy, constr->obj_class, &ps->obj_class_val);

	if (qpol_iterator_create(policy, (void *)ps, perm_state_get_cur,
				 perm_state_next, perm_state_end, perm_state_size, free, iter)) {
		free(ps);
		return STATUS_ERR;
	}

	if (!(ps->perm_set & 1))       /* defaults to bit 0 */
		qpol_iterator_next(*iter);

	return STATUS_SUCCESS;
}

typedef struct constr_expr_state
{
	constraint_expr_t *head;
	constraint_expr_t *cur;
} constr_expr_state_t;

static int constr_expr_state_end(const qpol_iterator_t * iter)
{
	constr_expr_state_t *ces = NULL;

	if (!iter || !(ces = (constr_expr_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return ces->cur ? 0 : 1;
}

static void *constr_expr_state_get_cur(const qpol_iterator_t * iter)
{
	constr_expr_state_t *ces = NULL;

	if (!iter || !(ces = (constr_expr_state_t *) qpol_iterator_state(iter)) || qpol_iterator_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	return ces->cur;
}

static int constr_expr_state_next(qpol_iterator_t * iter)
{
	constr_expr_state_t *ces = NULL;

	if (!iter || !(ces = (constr_expr_state_t *) qpol_iterator_state(iter))) {
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

static size_t constr_expr_state_size(const qpol_iterator_t * iter)
{
	constr_expr_state_t *ces = NULL;
	constraint_expr_t *tmp = NULL;
	size_t count = 0;

	if (!iter || !(ces = (constr_expr_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return 0;
	}

	for (tmp = ces->head; tmp; tmp = tmp->next)
		count++;

	return count;
}

int qpol_constraint_get_expr_iter(const qpol_policy_t * policy, const qpol_constraint_t * constr, qpol_iterator_t ** iter)
{
	constr_expr_state_t *ces = NULL;
	constraint_node_t *internal_constr = NULL;

	if (iter)
		*iter = NULL;

	if (!policy || !constr || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_constr = (constraint_node_t *) constr->constr;

	if (!(ces = calloc(1, sizeof(constr_expr_state_t)))) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return STATUS_ERR;
	}
	ces->head = ces->cur = internal_constr->expr;

	if (qpol_iterator_create(policy, (void *)ces,
				 constr_expr_state_get_cur, constr_expr_state_next,
				 constr_expr_state_end, constr_expr_state_size, free, iter)) {
		free(ces);
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

static int policy_constr_state_next_vtrans(qpol_iterator_t * iter)
{
	policy_constr_state_t *pcs = NULL;
	qpol_class_t *obj_class = NULL;

	if (!iter || !(pcs = (policy_constr_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (qpol_iterator_end(iter)) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	qpol_iterator_next(pcs->constr_iter);
	while (qpol_iterator_end(pcs->constr_iter)) {
		qpol_iterator_destroy(&pcs->constr_iter);
		qpol_iterator_next(pcs->class_iter);
		if (qpol_iterator_end(pcs->class_iter))
			return STATUS_SUCCESS;
		if (qpol_iterator_get_item(pcs->class_iter, (void **)&obj_class))
			return STATUS_ERR;
		if (qpol_class_get_validatetrans_iter(pcs->policy, obj_class, &pcs->constr_iter))
			return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

static size_t policy_constr_state_size_vtrans(const qpol_iterator_t * iter)
{
	policy_constr_state_t *pcs = NULL;
	qpol_class_t *obj_class = NULL;
	qpol_iterator_t *internal_iter = NULL, *constr_iter = NULL;
	size_t count = 0, tmp = 0;

	if (!iter || !(pcs = (policy_constr_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return 0;
	}

	if (qpol_policy_get_class_iter(pcs->policy, &internal_iter))
		return 0;

	for (; !qpol_iterator_end(internal_iter); qpol_iterator_next(internal_iter)) {
		if (qpol_iterator_get_item(internal_iter, (void **)&obj_class))
			goto err;
		if (qpol_class_get_validatetrans_iter(pcs->policy, obj_class, &constr_iter))
			goto err;
		if (qpol_iterator_get_size(constr_iter, &tmp))
			goto err;
		count += tmp;
		tmp = 0;
		qpol_iterator_destroy(&constr_iter);
	}

	qpol_iterator_destroy(&internal_iter);
	return count;

      err:
	qpol_iterator_destroy(&internal_iter);
	qpol_iterator_destroy(&constr_iter);
	return 0;
}

int qpol_policy_get_validatetrans_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
{
	policy_constr_state_t *pcs = NULL;
	int error = 0;
	qpol_class_t *tmp = NULL;

	if (iter)
		*iter = NULL;

	if (!policy || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (!(pcs = calloc(1, sizeof(policy_constr_state_t)))) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return STATUS_ERR;
	}
	pcs->policy = policy;
	if (qpol_policy_get_class_iter(policy, &pcs->class_iter)) {
		error = errno;
		goto err;
	}
	if (qpol_iterator_get_item(pcs->class_iter, (void **)&tmp)) {
		error = errno;
		ERR(policy, "Error getting first class: %s", strerror(error));
		goto err;
	}
	if (qpol_class_get_validatetrans_iter(policy, tmp, &pcs->constr_iter)) {
		error = errno;
		goto err;
	}

	if (qpol_iterator_create(policy, (void *)pcs,
				 policy_constr_state_get_cur, policy_constr_state_next_vtrans,
				 policy_constr_state_end, policy_constr_state_size_vtrans, policy_constr_state_free, iter)) {
		error = errno;
		goto err;
	}

	if (qpol_iterator_end(pcs->constr_iter)) {
		if (qpol_iterator_next(*iter)) {
			error = errno;
			pcs = NULL;    /* avoid double free, iterator will destroy this */
			ERR(policy, "Error finding first validatetrans: %s", strerror(error));
			goto err;
		}
	}

	return STATUS_SUCCESS;

      err:
	policy_constr_state_free(pcs);
	qpol_iterator_destroy(iter);
	errno = error;
	return STATUS_ERR;

}

int qpol_validatetrans_get_class(const qpol_policy_t * policy, const qpol_validatetrans_t * vtrans, const qpol_class_t ** obj_class)
{
	if (obj_class)
		*obj_class = NULL;

	if (!policy || !vtrans || !obj_class) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*obj_class = ((qpol_constraint_t *) vtrans)->obj_class;

	return STATUS_SUCCESS;
}

int qpol_validatetrans_get_expr_iter(const qpol_policy_t * policy, const qpol_validatetrans_t * vtrans, qpol_iterator_t ** iter)
{
	constr_expr_state_t *ces = NULL;
	constraint_node_t *internal_constr = NULL;

	if (iter)
		*iter = NULL;

	if (!policy || !vtrans || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_constr = (constraint_node_t *) ((qpol_constraint_t *) vtrans)->constr;

	if (!(ces = calloc(1, sizeof(constr_expr_state_t)))) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return STATUS_ERR;
	}
	ces->head = ces->cur = internal_constr->expr;

	if (qpol_iterator_create(policy, (void *)ces,
				 constr_expr_state_get_cur, constr_expr_state_next,
				 constr_expr_state_end, constr_expr_state_size, free, iter)) {
		free(ces);
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_constraint_expr_node_get_expr_type(const qpol_policy_t * policy, const qpol_constraint_expr_node_t * expr,
					    uint32_t * expr_type)
{
	constraint_expr_t *internal_expr = NULL;

	if (!policy || !expr || !expr_type) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_expr = (constraint_expr_t *) expr;

	*expr_type = internal_expr->expr_type;

	return STATUS_SUCCESS;
}

int qpol_constraint_expr_node_get_sym_type(const qpol_policy_t * policy, const qpol_constraint_expr_node_t * expr,
					   uint32_t * sym_type)
{
	constraint_expr_t *internal_expr = NULL;

	if (!policy || !expr || !sym_type) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_expr = (constraint_expr_t *) expr;

	*sym_type = internal_expr->attr;

	return STATUS_SUCCESS;
}

int qpol_constraint_expr_node_get_op(const qpol_policy_t * policy, const qpol_constraint_expr_node_t * expr, uint32_t * op)
{
	constraint_expr_t *internal_expr = NULL;

	if (!policy || !expr || !op) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_expr = (constraint_expr_t *) expr;

	*op = internal_expr->op;

	return STATUS_SUCCESS;
}

typedef struct cexpr_name_state
{
	ebitmap_t *inc;
	ebitmap_t *sub;
	size_t cur;
#define QPOL_CEXPR_NAME_STATE_INC_LIST 0
#define QPOL_CEXPR_NAME_STATE_SUB_LIST 1
	unsigned char list;
} cexpr_name_state_t;

static int cexpr_name_state_end(const qpol_iterator_t * iter)
{
	cexpr_name_state_t *cns = NULL;

	if (!iter || !(cns = (cexpr_name_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (cns->list == QPOL_CEXPR_NAME_STATE_SUB_LIST && (cns->sub ? cns->cur >= cns->sub->highbit : 1))
		return 1;

	return 0;
}

static int cexpr_name_state_next(qpol_iterator_t * iter)
{
	cexpr_name_state_t *cns = NULL;
	ebitmap_t *bmap = NULL;

	if (!iter || !(cns = (cexpr_name_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (qpol_iterator_end(iter)) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	bmap = (cns->list == QPOL_CEXPR_NAME_STATE_INC_LIST ? cns->inc : cns->sub);

	do {
		cns->cur++;
		if (cns->cur >= bmap->highbit) {
			if (cns->list == QPOL_CEXPR_NAME_STATE_INC_LIST) {
				cns->list = QPOL_CEXPR_NAME_STATE_SUB_LIST;
				cns->cur = 0;
				bmap = cns->sub;
				if (!bmap)
					break;
			} else {
				break;
			}
		}
	} while (!ebitmap_get_bit(bmap, cns->cur));

	return STATUS_SUCCESS;
}

static size_t cexpr_name_state_size(const qpol_iterator_t * iter)
{
	cexpr_name_state_t *cns = NULL;
	size_t count = 0, bit = 0;
	ebitmap_node_t *node = NULL;

	if (!iter || !(cns = (cexpr_name_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return 0;
	}

	ebitmap_for_each_bit(cns->inc, node, bit) {
		count += ebitmap_get_bit(cns->inc, bit);
	}

	if (!(cns->sub))
		return count;

	bit = 0;
	ebitmap_for_each_bit(cns->sub, node, bit) {
		count += ebitmap_get_bit(cns->sub, bit);
	}

	return count;
}

static void *cexpr_name_state_get_cur_user(const qpol_iterator_t * iter)
{
	cexpr_name_state_t *cns = NULL;
	const policydb_t *db = NULL;

	if (!iter || !(cns = (cexpr_name_state_t *) qpol_iterator_state(iter)) ||
	    !(db = qpol_iterator_policy(iter)) || qpol_iterator_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	return strdup(db->p_user_val_to_name[cns->cur]);
}

static void *cexpr_name_state_get_cur_role(const qpol_iterator_t * iter)
{
	cexpr_name_state_t *cns = NULL;
	const policydb_t *db = NULL;

	if (!iter || !(cns = (cexpr_name_state_t *) qpol_iterator_state(iter)) ||
	    !(db = qpol_iterator_policy(iter)) || qpol_iterator_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	return strdup(db->p_role_val_to_name[cns->cur]);
}

static void *cexpr_name_state_get_cur_type(const qpol_iterator_t * iter)
{
	cexpr_name_state_t *cns = NULL;
	const policydb_t *db = NULL;
	char *tmp = NULL, *name = NULL;
	size_t len = 0;

	if (!iter || !(cns = (cexpr_name_state_t *) qpol_iterator_state(iter)) ||
	    !(db = qpol_iterator_policy(iter)) || qpol_iterator_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	tmp = strdup(db->p_type_val_to_name[cns->cur]);

	if (cns->list == QPOL_CEXPR_NAME_STATE_INC_LIST)
		return tmp;

	len = strlen(tmp);
	name = calloc(len + 2, sizeof(char));
	if (!name) {
		free(tmp);
		errno = ENOMEM;
		return NULL;
	}
	len++;

	snprintf(name, len + 1, "-%s", tmp);
	free(tmp);

	return name;
}

int qpol_constraint_expr_node_get_names_iter(const qpol_policy_t * policy, const qpol_constraint_expr_node_t * expr,
					     qpol_iterator_t ** iter)
{
	constraint_expr_t *internal_expr = NULL;
	cexpr_name_state_t *cns = NULL;
	int policy_type = 0;

	if (iter)
		*iter = NULL;

	if (!policy || !expr || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (qpol_policy_get_type(policy, &policy_type))
		return STATUS_ERR;

	internal_expr = (constraint_expr_t *) expr;

	if (internal_expr->expr_type != QPOL_CEXPR_TYPE_NAMES) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (!(cns = calloc(1, sizeof(cexpr_name_state_t)))) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return STATUS_ERR;
	}
	if (internal_expr->attr & QPOL_CEXPR_SYM_TYPE) {
		if (policy_type == QPOL_POLICY_KERNEL_BINARY) {
			cns->inc = &(internal_expr->names);
		} else {
			cns->inc = &(internal_expr->type_names->types);
			cns->sub = &(internal_expr->type_names->negset);
		}
	} else {
		cns->inc = &(internal_expr->names);
	}
	cns->list = QPOL_CEXPR_NAME_STATE_INC_LIST;
	cns->cur = cns->inc->node ? cns->inc->node->startbit : 0;

	switch (internal_expr->attr & ~(QPOL_CEXPR_SYM_TARGET | QPOL_CEXPR_SYM_XTARGET)) {
	case QPOL_CEXPR_SYM_USER:
	{
		if (qpol_iterator_create(policy, (void *)cns,
					 cexpr_name_state_get_cur_user, cexpr_name_state_next,
					 cexpr_name_state_end, cexpr_name_state_size, free, iter)) {
			return STATUS_ERR;
		}
		break;
	}
	case QPOL_CEXPR_SYM_ROLE:
	{
		if (qpol_iterator_create(policy, (void *)cns,
					 cexpr_name_state_get_cur_role, cexpr_name_state_next,
					 cexpr_name_state_end, cexpr_name_state_size, free, iter)) {
			return STATUS_ERR;
		}
		break;
	}
	case QPOL_CEXPR_SYM_TYPE:
	{
		if (qpol_iterator_create(policy, (void *)cns,
					 cexpr_name_state_get_cur_type, cexpr_name_state_next,
					 cexpr_name_state_end, cexpr_name_state_size, free, iter)) {
			return STATUS_ERR;
		}
		break;
	}
	default:
	{
		ERR(policy, "%s", strerror(EINVAL));
		free(cns);
		errno = EINVAL;
		return STATUS_ERR;
	}
	}

	if (cns->inc->node && !ebitmap_get_bit(cns->inc, cns->cur))
		qpol_iterator_next(*iter);

	return STATUS_SUCCESS;
}

typedef struct class_constr_state
{
	constraint_node_t *head;
	constraint_node_t *cur;
	const qpol_class_t *obj_class;
} class_constr_state_t;

static int class_constr_state_end(const qpol_iterator_t * iter)
{
	class_constr_state_t *ccs = NULL;

	if (!iter || !(ccs = (class_constr_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return ccs->cur ? 0 : 1;
}

static void *class_constr_state_get_cur(const qpol_iterator_t * iter)
{
	class_constr_state_t *ccs = NULL;
	qpol_constraint_t *qc = NULL;

	if (!iter || !(ccs = (class_constr_state_t *) qpol_iterator_state(iter)) || qpol_iterator_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	if (!(qc = calloc(1, sizeof(qpol_constraint_t)))) {
		return NULL;	       /* errno set by calloc */
	}
	qc->obj_class = ccs->obj_class;
	qc->constr = ccs->cur;

	return qc;
}

static int class_constr_state_next(qpol_iterator_t * iter)
{
	class_constr_state_t *ccs = NULL;

	if (!iter || !(ccs = (class_constr_state_t *) qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (qpol_iterator_end(iter)) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	ccs->cur = ccs->cur->next;

	return STATUS_SUCCESS;
}

static size_t class_constr_state_size(const qpol_iterator_t * iter)
{
	class_constr_state_t *ccs = NULL;
	constraint_node_t *tmp = NULL;
	size_t count = 0;

	if (!iter || !(ccs = (class_constr_state_t *) qpol_iterator_state(iter)) || qpol_iterator_end(iter)) {
		errno = EINVAL;
		return 0;
	}

	for (tmp = ccs->head; tmp; tmp = tmp->next)
		count++;

	return count;
}

int qpol_class_get_constraint_iter(const qpol_policy_t * policy, const qpol_class_t * obj_class, qpol_iterator_t ** constr)
{
	const policydb_t *db = NULL;
	class_constr_state_t *ccs = NULL;
	class_datum_t *internal_class = NULL;
	int error = 0;

	if (constr)
		*constr = NULL;

	if (!policy || !obj_class || !constr) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_class = (class_datum_t *) obj_class;

	ccs = calloc(1, sizeof(class_constr_state_t));
	if (!ccs) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		errno = error;
		return STATUS_ERR;
	}
	ccs->obj_class = obj_class;
	ccs->head = ccs->cur = internal_class->constraints;

	if (qpol_iterator_create(policy, (void *)ccs, class_constr_state_get_cur,
				 class_constr_state_next, class_constr_state_end, class_constr_state_size, free, constr)) {
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_class_get_validatetrans_iter(const qpol_policy_t * policy, const qpol_class_t * obj_class, qpol_iterator_t ** vtrans)
{
	const policydb_t *db = NULL;
	class_constr_state_t *ccs = NULL;
	class_datum_t *internal_class = NULL;
	int error = 0;

	if (vtrans)
		*vtrans = NULL;

	if (!policy || !obj_class || !vtrans) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_class = (class_datum_t *) obj_class;

	ccs = calloc(1, sizeof(class_constr_state_t));
	if (!ccs) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		errno = error;
		return STATUS_ERR;
	}
	ccs->obj_class = obj_class;
	ccs->head = ccs->cur = internal_class->validatetrans;

	if (qpol_iterator_create(policy, (void *)ccs, class_constr_state_get_cur,
				 class_constr_state_next, class_constr_state_end, class_constr_state_size, free, vtrans)) {
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}
