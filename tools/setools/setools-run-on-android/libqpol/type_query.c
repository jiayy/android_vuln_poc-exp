/**
 *  @file
 *  Implementation of the interface for searching and iterating over types.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006-2008 Tresys Technology, LLC
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
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/expand.h>
#include "iterator_internal.h"
#include <qpol/type_query.h>
#include "qpol_internal.h"

int qpol_policy_get_type_by_name(const qpol_policy_t * policy, const char *name, const qpol_type_t ** datum)
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
	internal_datum = hashtab_search(db->p_types.table, (const hashtab_key_t)name);
	if (internal_datum == NULL) {
		*datum = NULL;
		ERR(policy, "could not find datum for type %s", name);
		errno = ENOENT;
		return STATUS_ERR;
	}
	*datum = (qpol_type_t *) internal_datum;

	return STATUS_SUCCESS;
}

int qpol_policy_get_type_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
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
	hs->table = &db->p_types.table;
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

int qpol_type_get_value(const qpol_policy_t * policy, const qpol_type_t * datum, uint32_t * value)
{
	type_datum_t *internal_datum;

	if (policy == NULL || datum == NULL || value == NULL) {
		if (value != NULL)
			*value = 0;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (type_datum_t *) datum;
	if (internal_datum->flavor == TYPE_ALIAS) {
		/* aliases that came from modules should use the value
		 * referenced to by that alias */
		*value = internal_datum->primary;
	} else {
		*value = internal_datum->s.value;
	}

	return STATUS_SUCCESS;
}

/**
 * Determine if a type_datum_t is an alias or a non-alias (primary
 * type or an attribute).  For aliases declared in base policies, they
 * will have no primary value and a flavor of TYPE_TYPE.  For aliases
 * declared in modules, they have a flavor of TYPE_ALIAS; their
 * primary value points to the new /linked/ type's value.
 *
 * @param datum Type datum to check.
 *
 * @return 1 if the datum is an alias, 0 if not.
 */
static int is_type_really_an_alias(const type_datum_t * datum)
{
	if (datum->primary == 0 && datum->flavor == TYPE_TYPE) {
		return 1;
	}
	if (datum->flavor == TYPE_ALIAS) {
		return 1;
	}
	return 0;
}

int qpol_type_get_isalias(const qpol_policy_t * policy, const qpol_type_t * datum, unsigned char *isalias)
{
	type_datum_t *internal_datum;

	if (policy == NULL || datum == NULL || isalias == NULL) {
		if (isalias != NULL)
			*isalias = 0;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
	internal_datum = (type_datum_t *) datum;
	*isalias = is_type_really_an_alias(internal_datum);

	return STATUS_SUCCESS;
}

int qpol_type_get_isattr(const qpol_policy_t * policy, const qpol_type_t * datum, unsigned char *isattr)
{
	type_datum_t *internal_datum;

	if (policy == NULL || datum == NULL || isattr == NULL) {
		if (isattr != NULL)
			*isattr = 0;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (type_datum_t *) datum;
	*isattr = (internal_datum->flavor == TYPE_ATTRIB ? 1 : 0);

	return STATUS_SUCCESS;
}

int qpol_type_get_ispermissive(const qpol_policy_t * policy, const qpol_type_t * datum, unsigned char *ispermissive)
{
	if (policy == NULL || datum == NULL || ispermissive == NULL) {
		if (ispermissive != NULL)
			*ispermissive = 0;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
#ifdef HAVE_SEPOL_PERMISSIVE_TYPES
	/* checking internal_datum->flags for permissive won't work,
	   because the type could be an alias.  so instead, look up
	   its value within the permissive map */
	uint32_t value;
	if (qpol_type_get_value(policy, datum, &value) < 0) {
		return STATUS_ERR;
	}
	policydb_t *p = &policy->p->p;
	/* note that unlike other bitmaps, this one does not subtract
	   1 in the bitmap */
	*ispermissive = ebitmap_get_bit(&p->permissive_map, value);
#else
	*ispermissive = 0;
#endif

	return STATUS_SUCCESS;
}

int qpol_type_get_type_iter(const qpol_policy_t * policy, const qpol_type_t * datum, qpol_iterator_t ** types)
{
	type_datum_t *internal_datum = NULL;
	ebitmap_state_t *es = NULL;
	int error = 0;

	if (types != NULL)
		*types = NULL;

	if (policy == NULL || datum == NULL || types == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (type_datum_t *) datum;

	if (internal_datum->flavor != TYPE_ATTRIB) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_NODATA;
	}

	es = calloc(1, sizeof(ebitmap_state_t));
	if (es == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}

	es->bmap = &(internal_datum->types);
	es->cur = es->bmap->node ? es->bmap->node->startbit : 0;

	if (qpol_iterator_create(policy, es, ebitmap_state_get_cur_type,
				 ebitmap_state_next, ebitmap_state_end, ebitmap_state_size, free, types)) {
		free(es);
		return STATUS_ERR;
	}

	if (es->bmap->node && !ebitmap_get_bit(es->bmap, es->cur))
		ebitmap_state_next(*types);

	return STATUS_SUCCESS;
}

int qpol_type_get_attr_iter(const qpol_policy_t * policy, const qpol_type_t * datum, qpol_iterator_t ** attrs)
{
	type_datum_t *internal_datum = NULL;
	ebitmap_state_t *es = NULL;
	int error = 0;

	if (attrs != NULL)
		*attrs = NULL;

	if (policy == NULL || datum == NULL || attrs == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (type_datum_t *) datum;

	if (internal_datum->flavor == TYPE_ATTRIB) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_NODATA;
	}

	es = calloc(1, sizeof(ebitmap_state_t));
	if (es == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}

	es->bmap = &(internal_datum->types);
	es->cur = es->bmap->node ? es->bmap->node->startbit : 0;

	if (qpol_iterator_create(policy, es, ebitmap_state_get_cur_type,
				 ebitmap_state_next, ebitmap_state_end, ebitmap_state_size, free, attrs)) {
		free(es);
		return STATUS_ERR;
	}

	if (es->bmap->node && !ebitmap_get_bit(es->bmap, es->cur))
		ebitmap_state_next(*attrs);

	return STATUS_SUCCESS;
}

int qpol_type_get_name(const qpol_policy_t * policy, const qpol_type_t * datum, const char **name)
{
	type_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;

	if (policy == NULL || datum == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_datum = (type_datum_t *) datum;

	*name = db->p_type_val_to_name[internal_datum->s.value - 1];

	return STATUS_SUCCESS;
}

typedef struct type_alias_hash_state
{
	unsigned int bucket;
	hashtab_node_t *node;
	hashtab_t *table;
	uint32_t val;
} type_alias_hash_state_t;

/**
 * For aliases that came from the base policy, their primary type is
 * referenced by s.value.  For aliases that came from modules, their
 * primary type is referenced by the primary field.
 *
 * @param datum Alias whose primary value to get.
 *
 * @return The primary type's identifier.
 */
static uint32_t get_alias_primary(const type_datum_t * datum)
{
	if (datum->flavor == TYPE_TYPE) {
		return datum->s.value;
	} else {
		return datum->primary;
	}
}

static int hash_state_next_type_alias(qpol_iterator_t * iter)
{
	type_alias_hash_state_t *hs = NULL;
	type_datum_t *datum = NULL;

	if (iter == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	hs = (type_alias_hash_state_t *) qpol_iterator_state(iter);
	if (hs == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (hs->bucket >= (*(hs->table))->size) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	do {
		hash_state_next(iter);
		datum = hs->node ? (type_datum_t *) hs->node->datum : NULL;
	} while (datum != NULL && (hs->val != get_alias_primary(datum) || !is_type_really_an_alias(datum)));

	return STATUS_SUCCESS;
}

static void *hash_state_get_cur_alias(const qpol_iterator_t * iter)
{
	type_alias_hash_state_t *hs = NULL;

	if (iter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	hs = (type_alias_hash_state_t *) qpol_iterator_state(iter);
	if (hs == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (hs->bucket >= (*(hs->table))->size) {
		errno = ERANGE;
		return NULL;
	}

	return hs->node->key;
}

static size_t hash_alias_state_size(const qpol_iterator_t * iter)
{
	type_alias_hash_state_t *hs = NULL;
	type_datum_t *tmp_datum;
	hashtab_node_t *tmp_node;
	uint32_t tmp_bucket = 0;
	size_t count = 0;

	if (iter == NULL || qpol_iterator_state(iter) == NULL) {
		errno = EINVAL;
		return 0;
	}

	hs = (type_alias_hash_state_t *) qpol_iterator_state(iter);

	for (tmp_bucket = 0; tmp_bucket < (*(hs->table))->size; tmp_bucket++) {
		for (tmp_node = (*(hs->table))->htable[tmp_bucket]; tmp_node; tmp_node = tmp_node->next) {
			tmp_datum = tmp_node ? tmp_node->datum : NULL;
			if (tmp_datum) {
				if (hs->val == get_alias_primary(tmp_datum) && is_type_really_an_alias(tmp_datum)) {
					count++;
				}
			}
		}
	}
	return count;
}

int qpol_type_get_alias_iter(const qpol_policy_t * policy, const qpol_type_t * datum, qpol_iterator_t ** aliases)
{
	type_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;
	int error = 0;
	type_alias_hash_state_t *hs = NULL;

	if (policy == NULL || datum == NULL || aliases == NULL) {
		if (aliases != NULL)
			*aliases = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_datum = (type_datum_t *) datum;

	hs = calloc(1, sizeof(type_alias_hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &db->p_types.table;
	hs->node = (*(hs->table))->htable[0];
	hs->val = get_alias_primary(internal_datum);

	if (qpol_iterator_create(policy, (void *)hs, hash_state_get_cur_alias,
				 hash_state_next_type_alias, hash_state_end, hash_alias_state_size, free, aliases)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL || hs->val != get_alias_primary((type_datum_t *) (hs->node->datum)) ||
	    !is_type_really_an_alias((type_datum_t *) hs->node->datum))
		hash_state_next_type_alias(*aliases);

	return STATUS_SUCCESS;
}
