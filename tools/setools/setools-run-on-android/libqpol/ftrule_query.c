/**
 *  @file
 *  Defines public interface for iterating over filename transition rules.
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
#include <qpol/ftrule_query.h>
#include <stdlib.h>
#include "iterator_internal.h"
#include "qpol_internal.h"
#include <sepol/policydb/policydb.h>

typedef struct filename_trans_item
{
	filename_trans_t *ft;
	filename_trans_datum_t *ftdatum;
	struct filename_trans_item *next;
} filename_trans_item_t;

typedef struct filename_trans_state
{
	filename_trans_item_t *head;
	filename_trans_item_t *cur;
} filename_trans_state_t;

static int filename_trans_state_end(const qpol_iterator_t * iter)
{
	filename_trans_state_t *fts = NULL;

	if (!iter || !(fts = qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return fts->cur ? 0 : 1;
}

static void *filename_trans_state_get_cur(const qpol_iterator_t * iter)
{
	filename_trans_state_t *fts = NULL;
	const policydb_t *db = NULL;

	if (!iter || !(fts = qpol_iterator_state(iter)) || !(db = qpol_iterator_policy(iter)) || filename_trans_state_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	return fts->cur;
}

static int filename_trans_state_next(qpol_iterator_t * iter)
{
	filename_trans_state_t *fts = NULL;
	const policydb_t *db = NULL;

	if (!iter || !(fts = qpol_iterator_state(iter)) || !(db = qpol_iterator_policy(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (filename_trans_state_end(iter)) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	fts->cur = fts->cur->next;

	return STATUS_SUCCESS;
}

static size_t filename_trans_state_size(const qpol_iterator_t * iter)
{
	filename_trans_state_t *fts = NULL;
	const policydb_t *db = NULL;
	filename_trans_item_t *tmp = NULL;
	size_t count = 0;

	if (!iter || !(fts = qpol_iterator_state(iter)) || !(db = qpol_iterator_policy(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	for (tmp = fts->head; tmp; tmp = tmp->next)
		count++;

	return count;
}

static int _hashmap_to_list(hashtab_key_t key, hashtab_datum_t datum, void *ptr)
{
	filename_trans_t *ft = (filename_trans_t *)key;
	filename_trans_datum_t *ftdatum = (filename_trans_datum_t *)datum;
	filename_trans_state_t *fts = ptr;
	filename_trans_item_t *fti;

	fti = calloc(1, sizeof(*fti));
	if (fti == NULL) {
		errno = ENOMEM;
		return STATUS_ERR;
	}
	fti->ft = ft;
	fti->ftdatum = ftdatum;
	fti->next = fts->head;
	fts->head = fti;

	return STATUS_SUCCESS;
}

int qpol_policy_get_filename_trans_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
{
	policydb_t *db = NULL;
	filename_trans_state_t *fts = NULL;
	int error = 0;

	if (iter)
		*iter = NULL;

	if (!policy || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	fts = calloc(1, sizeof(filename_trans_state_t));
	if (!fts) {
		/* errno set by calloc */
		ERR(policy, "%s", strerror(errno));
		return STATUS_ERR;
	}

	hashtab_map(db->filename_trans, _hashmap_to_list, fts);
	fts->cur = fts->head;

	if (qpol_iterator_create
	    (policy, (void *)fts, filename_trans_state_get_cur, filename_trans_state_next, filename_trans_state_end, filename_trans_state_size,
	     free, iter)) {
		error = errno;
		free(fts);
		errno = error;
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_filename_trans_get_source_type(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const qpol_type_t ** source)
{
	policydb_t *db = NULL;
	filename_trans_t *ft = NULL;

	if (source) {
		*source = NULL;
	}

	if (!policy || !rule || !source) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	ft = ((filename_trans_item_t *)rule)->ft;

	*source = (qpol_type_t *) db->type_val_to_struct[ft->stype - 1];

	return STATUS_SUCCESS;
}

int qpol_filename_trans_get_target_type(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const qpol_type_t ** target)
{
	policydb_t *db = NULL;
	filename_trans_t *ft = NULL;

	if (target) {
		*target = NULL;
	}

	if (!policy || !rule || !target) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	ft = ((filename_trans_item_t *)rule)->ft;

	*target = (qpol_type_t *) db->type_val_to_struct[ft->ttype - 1];

	return STATUS_SUCCESS;
}

int qpol_filename_trans_get_object_class(const qpol_policy_t * policy, const qpol_filename_trans_t * rule,
						const qpol_class_t ** obj_class)
{
	policydb_t *db = NULL;
	filename_trans_t *ft = NULL;

	if (obj_class) {
		*obj_class = NULL;
	}

	if (!policy || !rule || !obj_class) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	ft = ((filename_trans_item_t *)rule)->ft;

	*obj_class = (qpol_class_t *) db->class_val_to_struct[ft->tclass - 1];

	return STATUS_SUCCESS;
}

int qpol_filename_trans_get_default_type(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const qpol_type_t ** dflt)
{
	policydb_t *db = NULL;
	filename_trans_item_t *fti = NULL;

	if (dflt) {
		*dflt = NULL;
	}

	if (!policy || !rule || !dflt) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	fti = (filename_trans_item_t *) rule;

	*dflt = (qpol_type_t *) db->type_val_to_struct[fti->ftdatum->otype - 1];

	return STATUS_SUCCESS;
}

int qpol_filename_trans_get_filename(const qpol_policy_t * policy, const qpol_filename_trans_t * rule, const char ** name)
{
	filename_trans_t *ft = NULL;

	if (name) {
		*name = NULL;
	}

	if (!policy || !rule || !name) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	ft = ((filename_trans_item_t *)rule)->ft;

	*name = ft->name;

	return STATUS_SUCCESS;
}

