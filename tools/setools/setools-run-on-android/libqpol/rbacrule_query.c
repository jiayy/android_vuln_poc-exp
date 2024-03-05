/**
 *  @file
 *  Defines public interface for iterating over RBAC rules.
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

#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/rbacrule_query.h>
#include <stdlib.h>
#include "iterator_internal.h"
#include "qpol_internal.h"
#include <sepol/policydb/policydb.h>

typedef struct role_allow_state
{
	role_allow_t *head;
	role_allow_t *cur;
} role_allow_state_t;

static int role_allow_state_end(const qpol_iterator_t * iter)
{
	role_allow_state_t *ras = NULL;

	if (!iter || !(ras = qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return ras->cur ? 0 : 1;
}

static void *role_allow_state_get_cur(const qpol_iterator_t * iter)
{
	role_allow_state_t *ras = NULL;
	const policydb_t *db = NULL;

	if (!iter || !(ras = qpol_iterator_state(iter)) || !(db = qpol_iterator_policy(iter)) || role_allow_state_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	return ras->cur;
}

static int role_allow_state_next(qpol_iterator_t * iter)
{
	role_allow_state_t *ras = NULL;
	const policydb_t *db = NULL;

	if (!iter || !(ras = qpol_iterator_state(iter)) || !(db = qpol_iterator_policy(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (role_allow_state_end(iter)) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	ras->cur = ras->cur->next;

	return STATUS_SUCCESS;
}

static size_t role_allow_state_size(const qpol_iterator_t * iter)
{
	role_allow_state_t *ras = NULL;
	const policydb_t *db = NULL;
	role_allow_t *tmp = NULL;
	size_t count = 0;

	if (!iter || !(ras = qpol_iterator_state(iter)) || !(db = qpol_iterator_policy(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	for (tmp = ras->head; tmp; tmp = tmp->next)
		count++;

	return count;
}

int qpol_policy_get_role_allow_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
{
	policydb_t *db = NULL;
	role_allow_state_t *ras = NULL;
	int error = 0;

	if (iter)
		*iter = NULL;

	if (!policy || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	ras = calloc(1, sizeof(role_allow_state_t));
	if (!ras) {
		/* errno set by calloc */
		ERR(policy, "%s", strerror(errno));
		return STATUS_ERR;
	}
	ras->head = ras->cur = db->role_allow;

	if (qpol_iterator_create
	    (policy, (void *)ras, role_allow_state_get_cur, role_allow_state_next, role_allow_state_end, role_allow_state_size,
	     free, iter)) {
		error = errno;
		free(ras);
		errno = error;
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_role_allow_get_source_role(const qpol_policy_t * policy, const qpol_role_allow_t * rule, const qpol_role_t ** source)
{
	policydb_t *db = NULL;
	role_allow_t *ra = NULL;

	if (source) {
		*source = NULL;
	}

	if (!policy || !rule || !source) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	ra = (role_allow_t *) rule;

	*source = (qpol_role_t *) db->role_val_to_struct[ra->role - 1];

	return STATUS_SUCCESS;
}

int qpol_role_allow_get_target_role(const qpol_policy_t * policy, const qpol_role_allow_t * rule, const qpol_role_t ** target)
{
	policydb_t *db = NULL;
	role_allow_t *ra = NULL;

	if (target) {
		*target = NULL;
	}

	if (!policy || !rule || !target) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	ra = (role_allow_t *) rule;

	*target = (qpol_role_t *) db->role_val_to_struct[ra->new_role - 1];

	return STATUS_SUCCESS;
}

typedef struct role_trans_state
{
	role_trans_t *head;
	role_trans_t *cur;
} role_trans_state_t;

static int role_trans_state_end(const qpol_iterator_t * iter)
{
	role_trans_state_t *rts = NULL;

	if (!iter || !(rts = qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return rts->cur ? 0 : 1;
}

static void *role_trans_state_get_cur(const qpol_iterator_t * iter)
{
	role_trans_state_t *rts = NULL;
	const policydb_t *db = NULL;

	if (!iter || !(rts = qpol_iterator_state(iter)) || !(db = qpol_iterator_policy(iter)) || role_trans_state_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	return rts->cur;
}

static int role_trans_state_next(qpol_iterator_t * iter)
{
	role_trans_state_t *rts = NULL;
	const policydb_t *db = NULL;

	if (!iter || !(rts = qpol_iterator_state(iter)) || !(db = qpol_iterator_policy(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (role_trans_state_end(iter)) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	rts->cur = rts->cur->next;

	return STATUS_SUCCESS;
}

static size_t role_trans_state_size(const qpol_iterator_t * iter)
{
	role_trans_state_t *rts = NULL;
	const policydb_t *db = NULL;
	role_trans_t *tmp = NULL;
	size_t count = 0;

	if (!iter || !(rts = qpol_iterator_state(iter)) || !(db = qpol_iterator_policy(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	for (tmp = rts->head; tmp; tmp = tmp->next)
		count++;

	return count;
}

int qpol_policy_get_role_trans_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
{
	policydb_t *db = NULL;
	role_trans_state_t *rts = NULL;
	int error = 0;

	if (iter)
		*iter = NULL;

	if (!policy || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	rts = calloc(1, sizeof(role_trans_state_t));
	if (!rts) {
		/* errno set by calloc */
		ERR(policy, "%s", strerror(errno));
		return STATUS_ERR;
	}
	rts->head = rts->cur = db->role_tr;

	if (qpol_iterator_create
	    (policy, (void *)rts, role_trans_state_get_cur, role_trans_state_next, role_trans_state_end, role_trans_state_size,
	     free, iter)) {
		error = errno;
		free(rts);
		errno = error;
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_role_trans_get_source_role(const qpol_policy_t * policy, const qpol_role_trans_t * rule, const qpol_role_t ** source)
{
	policydb_t *db = NULL;
	role_trans_t *rt = NULL;

	if (source) {
		*source = NULL;
	}

	if (!policy || !rule || !source) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	rt = (role_trans_t *) rule;

	*source = (qpol_role_t *) db->role_val_to_struct[rt->role - 1];

	return STATUS_SUCCESS;
}

int qpol_role_trans_get_target_type(const qpol_policy_t * policy, const qpol_role_trans_t * rule, const qpol_type_t ** target)
{
	policydb_t *db = NULL;
	role_trans_t *rt = NULL;

	if (target) {
		*target = NULL;
	}

	if (!policy || !rule || !target) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	rt = (role_trans_t *) rule;

	*target = (qpol_type_t *) db->type_val_to_struct[rt->type - 1];

	return STATUS_SUCCESS;
}

int qpol_role_trans_get_default_role(const qpol_policy_t * policy, const qpol_role_trans_t * rule, const qpol_role_t ** dflt)
{
	policydb_t *db = NULL;
	role_trans_t *rt = NULL;

	if (dflt) {
		*dflt = NULL;
	}

	if (!policy || !rule || !dflt) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	rt = (role_trans_t *) rule;

	*dflt = (qpol_role_t *) db->role_val_to_struct[rt->new_role - 1];

	return STATUS_SUCCESS;
}
