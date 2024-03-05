/**
 *  @file
 *  Implementation of the interface for searching and iterating over users.
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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/expand.h>

#include <qpol/iterator.h>
#include <qpol/mls_query.h>
#include <qpol/policy.h>
#include <qpol/role_query.h>
#include <qpol/user_query.h>
#include "iterator_internal.h"
#include "qpol_internal.h"

int qpol_policy_get_user_by_name(const qpol_policy_t * policy, const char *name, const qpol_user_t ** datum)
{
	hashtab_datum_t internal_datum;
	policydb_t *db;

	if (policy == NULL || name == NULL || datum == NULL) {
		if (datum != NULL)
			*datum = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_datum = hashtab_search(db->p_users.table, (const hashtab_key_t)name);
	if (internal_datum == NULL) {
		*datum = NULL;
		ERR(policy, "could not find datum for user %s", name);
		errno = ENOENT;
		return STATUS_ERR;
	}
	*datum = (qpol_user_t *) internal_datum;

	return STATUS_SUCCESS;
}

int qpol_policy_get_user_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
{
	policydb_t *db;
	hash_state_t *hs = NULL;
	int error = 0;

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
	hs->table = &db->p_users.table;
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

int qpol_user_get_value(const qpol_policy_t * policy, const qpol_user_t * datum, uint32_t * value)
{
	user_datum_t *internal_datum;

	if (policy == NULL || datum == NULL || value == NULL) {
		if (value != NULL)
			*value = 0;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (user_datum_t *) datum;
	*value = internal_datum->s.value;

	return STATUS_SUCCESS;
}

int qpol_user_get_role_iter(const qpol_policy_t * policy, const qpol_user_t * datum, qpol_iterator_t ** roles)
{
	user_datum_t *internal_datum = NULL;
	int error = 0;
	ebitmap_state_t *es = NULL;

	if (policy == NULL || datum == NULL || roles == NULL) {
		if (roles != NULL)
			*roles = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (user_datum_t *) datum;

	es = calloc(1, sizeof(ebitmap_state_t));
	if (es == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}

	es->bmap = &(internal_datum->roles.roles);
	es->cur = es->bmap->node ? es->bmap->node->startbit : 0;

	if (qpol_iterator_create(policy, es, ebitmap_state_get_cur_role,
				 ebitmap_state_next, ebitmap_state_end, ebitmap_state_size, free, roles)) {
		free(es);
		return STATUS_ERR;
	}

	if (es->bmap->node && !ebitmap_get_bit(es->bmap, es->cur))
		ebitmap_state_next(*roles);

	return STATUS_SUCCESS;
}

int qpol_user_get_range(const qpol_policy_t * policy, const qpol_user_t * datum, const qpol_mls_range_t ** range)
{
	user_datum_t *internal_datum = NULL;

	if (policy == NULL || datum == NULL || range == NULL) {
		if (range != NULL)
			*range = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (!qpol_policy_has_capability(policy, QPOL_CAP_MLS)) {
		*range = NULL;
	} else {
		internal_datum = (user_datum_t *) datum;
		*range = (qpol_mls_range_t *) & internal_datum->exp_range;
	}
	return STATUS_SUCCESS;
}

int qpol_user_get_dfltlevel(const qpol_policy_t * policy, const qpol_user_t * datum, const qpol_mls_level_t ** level)
{
	user_datum_t *internal_datum = NULL;

	if (policy == NULL || datum == NULL || level == NULL) {
		if (level != NULL)
			*level = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (!qpol_policy_has_capability(policy, QPOL_CAP_MLS)) {
		*level = NULL;
	} else {
		internal_datum = (user_datum_t *) datum;
		*level = (qpol_mls_level_t *) & internal_datum->exp_dfltlevel;
	}
	return STATUS_SUCCESS;
}

int qpol_user_get_name(const qpol_policy_t * policy, const qpol_user_t * datum, const char **name)
{
	user_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;

	if (policy == NULL || datum == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_datum = (user_datum_t *) datum;

	*name = db->p_user_val_to_name[internal_datum->s.value - 1];

	return STATUS_SUCCESS;
}
