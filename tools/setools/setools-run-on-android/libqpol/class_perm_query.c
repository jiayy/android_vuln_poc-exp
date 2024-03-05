/**
 *  @file
 *  Implementation of the interface for searching and iterating over
 *  classes, commons, and permissions.
 *
 *  @author Kevin Carr kcarr@tresys.com
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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <qpol/iterator.h>
#include <sepol/policydb.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/expand.h>
#include "iterator_internal.h"
#include <qpol/class_perm_query.h>
#include "qpol_internal.h"

/* perms */
typedef struct perm_hash_state
{
	unsigned int bucket;
	hashtab_node_t *node;
	hashtab_t *table;
	const char *perm_name;
} perm_hash_state_t;

static int hash_state_next_class_w_perm(qpol_iterator_t * iter)
{
	class_datum_t *internal_class = NULL;
	qpol_iterator_t *internal_perms = NULL;
	unsigned char has_perm = 0;
	perm_hash_state_t *hs = NULL;
	sepol_policydb_t sp;
	qpol_policy_t qp;
	char *tmp = NULL;

	hs = (perm_hash_state_t *) qpol_iterator_state(iter);
	if (hs == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (hs->bucket >= (*(hs->table))->size) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	/* shallow copy ok here as only internal values are used */
	sp.p = *qpol_iterator_policy(iter);
	qp.p = &sp;
	qp.fn = NULL;

	do {
		hash_state_next(iter);
		if (hash_state_end(iter))
			break;
		internal_class = hs->node ? (class_datum_t *) hs->node->datum : NULL;
		qpol_class_get_perm_iter(&qp, (qpol_class_t *) internal_class, &internal_perms);
		for (; !qpol_iterator_end(internal_perms); qpol_iterator_next(internal_perms)) {
			qpol_iterator_get_item(internal_perms, (void **)&tmp);
			if (!strcmp(tmp, hs->perm_name)) {
				has_perm = 1;
				break;
			}
		}
		qpol_iterator_destroy(&internal_perms);
	} while (!has_perm && !hash_state_end(iter));

	return STATUS_SUCCESS;
}

static size_t hash_perm_state_size_common(const qpol_iterator_t * iter)
{
	perm_hash_state_t *hs = NULL;
	uint32_t tmp_bucket = 0;
	size_t count = 0;
	hashtab_node_t *tmp_node;
	sepol_policydb_t sp;
	qpol_policy_t qp;
	qpol_iterator_t *internal_perms;
	common_datum_t *internal_common;
	char *tmp = NULL;

	if (iter == NULL || qpol_iterator_state(iter) == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	hs = (perm_hash_state_t *) qpol_iterator_state(iter);
	if (hs == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	/* shallow copy ok here as only internal values are used */
	sp.p = *qpol_iterator_policy(iter);
	if (&sp.p == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	qp.p = &sp;
	qp.fn = NULL;
	for (tmp_bucket = 0; tmp_bucket < (*(hs->table))->size; tmp_bucket++) {
		for (tmp_node = (*(hs->table))->htable[tmp_bucket]; tmp_node; tmp_node = tmp_node->next) {
			internal_common = tmp_node ? ((common_datum_t *) tmp_node->datum) : NULL;
			qpol_common_get_perm_iter(&qp, (qpol_common_t *) internal_common, &internal_perms);
			for (; !qpol_iterator_end(internal_perms); qpol_iterator_next(internal_perms)) {
				qpol_iterator_get_item(internal_perms, (void **)&tmp);
				if (!strcmp(tmp, hs->perm_name)) {
					count++;
					break;
				}
			}
			qpol_iterator_destroy(&internal_perms);
		}
	}

	return count;
}

static size_t hash_perm_state_size_class(const qpol_iterator_t * iter)
{
	perm_hash_state_t *hs = NULL;
	uint32_t tmp_bucket = 0;
	size_t count = 0;
	hashtab_node_t *tmp_node;
	sepol_policydb_t sp;
	qpol_policy_t qp;
	qpol_iterator_t *internal_perms;
	class_datum_t *internal_class;
	char *tmp = NULL;

	if (iter == NULL || qpol_iterator_state(iter) == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	hs = (perm_hash_state_t *) qpol_iterator_state(iter);
	if (hs == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	/* shallow copy ok here as only internal values are used */
	sp.p = *qpol_iterator_policy(iter);
	qp.p = &sp;
	qp.fn = NULL;
	if (&sp.p == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	for (tmp_bucket = 0; tmp_bucket < (*(hs->table))->size; tmp_bucket++) {
		for (tmp_node = (*(hs->table))->htable[tmp_bucket]; tmp_node; tmp_node = tmp_node->next) {
			internal_class = tmp_node ? ((class_datum_t *) tmp_node->datum) : NULL;
			qpol_class_get_perm_iter(&qp, (qpol_class_t *) internal_class, &internal_perms);
			for (; !qpol_iterator_end(internal_perms); qpol_iterator_next(internal_perms)) {
				qpol_iterator_get_item(internal_perms, (void **)&tmp);
				if (!strcmp(tmp, hs->perm_name)) {
					count++;
					break;
				}
			}
			qpol_iterator_destroy(&internal_perms);
		}
	}

	return count;
}

static int hash_state_next_common_w_perm(qpol_iterator_t * iter)
{
	common_datum_t *internal_common = NULL;
	qpol_iterator_t *internal_perms = NULL;
	unsigned char has_perm = 0;
	perm_hash_state_t *hs = NULL;
	sepol_policydb_t sp;
	qpol_policy_t qp;
	char *tmp = NULL;

	hs = (perm_hash_state_t *) qpol_iterator_state(iter);
	if (hs == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (hs->bucket >= (*(hs->table))->size) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	/* shallow copy ok here as only internal values are used */
	sp.p = *qpol_iterator_policy(iter);
	qp.p = &sp;
	qp.fn = NULL;

	do {
		hash_state_next(iter);
		if (hash_state_end(iter))
			break;
		internal_common = hs->node ? (common_datum_t *) hs->node->datum : NULL;
		qpol_common_get_perm_iter(&qp, (qpol_common_t *) internal_common, &internal_perms);
		for (; !qpol_iterator_end(internal_perms); qpol_iterator_next(internal_perms)) {
			qpol_iterator_get_item(internal_perms, (void **)&tmp);
			if (!strcmp(tmp, hs->perm_name)) {
				has_perm = 1;
				break;
			}
		}
		qpol_iterator_destroy(&internal_perms);
	} while (!has_perm && !hash_state_end(iter));

	return STATUS_SUCCESS;
}

static int qpol_class_has_perm(const qpol_policy_t * p, const qpol_class_t * class, const char *perm)
{
	qpol_iterator_t *iter = NULL;
	char *tmp;

	qpol_class_get_perm_iter(p, class, &iter);
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_iterator_get_item(iter, (void **)&tmp);
		if (!strcmp(perm, tmp)) {
			qpol_iterator_destroy(&iter);
			return 1;
		}
	}
	qpol_iterator_destroy(&iter);
	return 0;
}

static int qpol_common_has_perm(const qpol_policy_t * p, const qpol_common_t * common, const char *perm)
{
	qpol_iterator_t *iter = NULL;
	char *tmp;

	qpol_common_get_perm_iter(p, common, &iter);
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_iterator_get_item(iter, (void **)&tmp);
		if (!strcmp(perm, tmp)) {
			qpol_iterator_destroy(&iter);
			return 1;
		}
	}
	qpol_iterator_destroy(&iter);
	return 0;
}

int qpol_perm_get_class_iter(const qpol_policy_t * policy, const char *perm, qpol_iterator_t ** classes)
{
	policydb_t *db;
	int error = 0;
	perm_hash_state_t *hs = NULL;

	if (policy == NULL || classes == NULL) {
		if (classes != NULL)
			*classes = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	hs = calloc(1, sizeof(perm_hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &db->p_classes.table;
	hs->node = (*(hs->table))->htable[0];
	hs->perm_name = perm;

	if (qpol_iterator_create(policy, (void *)hs, hash_state_get_cur,
				 hash_state_next_class_w_perm, hash_state_end, hash_perm_state_size_class, free, classes)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL || !qpol_class_has_perm(policy, (qpol_class_t *) hs->node->datum, perm))
		hash_state_next_class_w_perm(*classes);

	return STATUS_SUCCESS;
}

int qpol_perm_get_common_iter(const qpol_policy_t * policy, const char *perm, qpol_iterator_t ** commons)
{
	policydb_t *db;
	int error = 0;
	perm_hash_state_t *hs = NULL;

	if (policy == NULL || commons == NULL) {
		if (commons != NULL)
			*commons = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	hs = calloc(1, sizeof(perm_hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &db->p_commons.table;
	hs->node = (*(hs->table))->htable[0];
	hs->perm_name = perm;

	if (qpol_iterator_create(policy, (void *)hs, hash_state_get_cur,
				 hash_state_next_common_w_perm, hash_state_end, hash_perm_state_size_common, free, commons)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL || !qpol_common_has_perm(policy, (qpol_common_t *) hs->node->datum, perm))
		hash_state_next_common_w_perm(*commons);

	return STATUS_SUCCESS;
}

/* classes */
int qpol_policy_get_class_by_name(const qpol_policy_t * policy, const char *name, const qpol_class_t ** obj_class)
{
	hashtab_datum_t internal_datum;
	policydb_t *db;

	if (policy == NULL || name == NULL || obj_class == NULL) {
		if (obj_class != NULL)
			*obj_class = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_datum = hashtab_search(db->p_classes.table, (const hashtab_key_t)name);
	if (internal_datum == NULL) {
		*obj_class = NULL;
		ERR(policy, "could not find class %s", name);
		errno = ENOENT;
		return STATUS_ERR;
	}

	*obj_class = (qpol_class_t *) internal_datum;

	return STATUS_SUCCESS;
}

int qpol_policy_get_class_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
{
	policydb_t *db;
	int error = 0;
	hash_state_t *hs = NULL;

	if (policy == NULL || iter == NULL) {
		if (iter != NULL)
			*iter = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	hs = calloc(1, sizeof(hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &db->p_classes.table;
	hs->node = (*(hs->table))->htable[0];

	if (qpol_iterator_create(policy, (void *)hs, hash_state_get_cur,
				 hash_state_next, hash_state_end, hash_state_size, free, iter)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL)
		hash_state_next(*iter);

	return STATUS_SUCCESS;
}

int qpol_class_get_value(const qpol_policy_t * policy, const qpol_class_t * obj_class, uint32_t * value)
{
	class_datum_t *internal_datum;

	if (policy == NULL || obj_class == NULL || value == NULL) {
		if (value != NULL)
			*value = 0;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (class_datum_t *) obj_class;
	*value = internal_datum->s.value;

	return STATUS_SUCCESS;
}

int qpol_class_get_common(const qpol_policy_t * policy, const qpol_class_t * obj_class, const qpol_common_t ** common)
{
	class_datum_t *internal_datum = NULL;

	if (policy == NULL || obj_class == NULL || common == NULL) {
		if (common != NULL)
			*common = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (class_datum_t *) obj_class;
	*common = (qpol_common_t *) internal_datum->comdatum;

	return STATUS_SUCCESS;
}

int qpol_class_get_perm_iter(const qpol_policy_t * policy, const qpol_class_t * obj_class, qpol_iterator_t ** perms)
{
	class_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;
	int error = 0;
	hash_state_t *hs = NULL;

	if (policy == NULL || obj_class == NULL || perms == NULL) {
		if (perms != NULL)
			*perms = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (class_datum_t *) obj_class;
	db = &policy->p->p;

	hs = calloc(1, sizeof(hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &internal_datum->permissions.table;
	if (hs->table && *(hs->table)) {
		hs->node = (*(hs->table))->htable[0];
	} else {		       /* object class has no permissions */
		hs->node = NULL;
	}

	if (qpol_iterator_create(policy, (void *)hs, hash_state_get_cur_key,
				 hash_state_next, hash_state_end, hash_state_size, free, perms)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL)
		hash_state_next(*perms);

	return STATUS_SUCCESS;
}

int qpol_class_get_name(const qpol_policy_t * policy, const qpol_class_t * obj_class, const char **name)
{
	class_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;

	if (policy == NULL || obj_class == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_datum = (class_datum_t *) obj_class;

	*name = db->p_class_val_to_name[internal_datum->s.value - 1];

	return STATUS_SUCCESS;
}

/* commons */
int qpol_policy_get_common_by_name(const qpol_policy_t * policy, const char *name, const qpol_common_t ** common)
{
	hashtab_datum_t internal_datum;
	policydb_t *db;

	if (policy == NULL || name == NULL || common == NULL) {
		if (common != NULL)
			*common = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_datum = hashtab_search(db->p_commons.table, (const hashtab_key_t)name);
	if (internal_datum == NULL) {
		*common = NULL;
		ERR(policy, "could not find common %s", name);
		errno = ENOENT;
		return STATUS_ERR;
	}
	*common = (qpol_common_t *) internal_datum;

	return STATUS_SUCCESS;
}

int qpol_policy_get_common_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
{
	policydb_t *db;
	int error = 0;
	hash_state_t *hs = NULL;

	if (policy == NULL || iter == NULL) {
		if (iter != NULL)
			*iter = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	hs = calloc(1, sizeof(hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &db->p_commons.table;
	hs->node = (*(hs->table))->htable[0];

	if (qpol_iterator_create(policy, (void *)hs, hash_state_get_cur,
				 hash_state_next, hash_state_end, hash_state_size, free, iter)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL)
		hash_state_next(*iter);

	return STATUS_SUCCESS;
}

int qpol_common_get_value(const qpol_policy_t * policy, const qpol_common_t * common, uint32_t * value)
{
	common_datum_t *internal_datum;

	if (policy == NULL || common == NULL || value == NULL) {
		if (value != NULL)
			*value = 0;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (common_datum_t *) common;
	*value = internal_datum->s.value;

	return STATUS_SUCCESS;
}

int qpol_common_get_perm_iter(const qpol_policy_t * policy, const qpol_common_t * common, qpol_iterator_t ** perms)
{
	common_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;
	int error = 0;
	hash_state_t *hs = NULL;

	if (policy == NULL || common == NULL || perms == NULL) {
		if (perms != NULL)
			*perms = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (common_datum_t *) common;
	db = &policy->p->p;

	hs = calloc(1, sizeof(hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &internal_datum->permissions.table;
	hs->node = (*(hs->table))->htable[0];

	if (qpol_iterator_create(policy, (void *)hs, hash_state_get_cur_key,
				 hash_state_next, hash_state_end, hash_state_size, free, perms)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL)
		hash_state_next(*perms);

	return STATUS_SUCCESS;
}

int qpol_common_get_name(const qpol_policy_t * policy, const qpol_common_t * common, const char **name)
{
	common_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;

	if (policy == NULL || common == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_datum = (common_datum_t *) common;

	*name = db->p_common_val_to_name[internal_datum->s.value - 1];

	return STATUS_SUCCESS;
}
