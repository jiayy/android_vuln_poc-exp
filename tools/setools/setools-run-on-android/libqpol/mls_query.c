/**
 *  @file
 *  Implementation of the interface for searching and iterating over
 *  policy MLS components.
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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <qpol/iterator.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/expand.h>
#include "iterator_internal.h"
#include <qpol/mls_query.h>
#include "qpol_internal.h"

/* level */
int qpol_policy_get_level_by_name(const qpol_policy_t * policy, const char *name, const qpol_level_t ** datum)
{
	policydb_t *db = NULL;
	hashtab_datum_t internal_datum = NULL;

	if (policy == NULL || name == NULL || datum == NULL) {
		if (datum != NULL)
			*datum = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
	db = &policy->p->p;
	internal_datum = hashtab_search(db->p_levels.table, (const hashtab_key_t)name);
	if (internal_datum == NULL) {
		ERR(policy, "could not find datum for level %s", name);
		errno = ENOENT;
		return STATUS_ERR;
	}
	*datum = (qpol_level_t *) internal_datum;

	return STATUS_SUCCESS;
}

int qpol_policy_get_level_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
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
	hs->table = &db->p_levels.table;
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

int qpol_level_get_isalias(const qpol_policy_t * policy, const qpol_level_t * datum, unsigned char *isalias)
{
	level_datum_t *internal_datum;

	if (policy == NULL || datum == NULL || isalias == NULL) {
		if (isalias != NULL)
			*isalias = 0;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (level_datum_t *) datum;
	*isalias = internal_datum->isalias;

	return STATUS_SUCCESS;
}

int qpol_level_get_value(const qpol_policy_t * policy, const qpol_level_t * datum, uint32_t * value)
{
	level_datum_t *internal_datum = NULL;

	if (policy == NULL || datum == NULL || value == NULL) {
		if (value != NULL)
			*value = 0;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (level_datum_t *) datum;
	*value = internal_datum->level->sens;

	return STATUS_SUCCESS;
}

int qpol_level_get_cat_iter(const qpol_policy_t * policy, const qpol_level_t * datum, qpol_iterator_t ** cats)
{
	level_datum_t *internal_datum = NULL;
	ebitmap_state_t *es = NULL;
	int error = 0;

	if (policy == NULL || datum == NULL || cats == NULL) {
		if (cats != NULL)
			*cats = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (level_datum_t *) datum;

	es = calloc(1, sizeof(ebitmap_state_t));
	if (es == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}

	es->bmap = &(internal_datum->level->cat);
	es->cur = es->bmap->node ? es->bmap->node->startbit : 0;

	if (qpol_iterator_create(policy, es, ebitmap_state_get_cur_cat,
				 ebitmap_state_next, ebitmap_state_end, ebitmap_state_size, free, cats)) {
		free(es);
		return STATUS_ERR;
	}

	if (es->bmap->node && !ebitmap_get_bit(es->bmap, es->cur))
		ebitmap_state_next(*cats);

	return STATUS_SUCCESS;
}

int qpol_level_get_name(const qpol_policy_t * policy, const qpol_level_t * datum, const char **name)
{
	level_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;

	if (policy == NULL || datum == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_datum = (level_datum_t *) datum;

	*name = db->p_sens_val_to_name[internal_datum->level->sens - 1];

	return STATUS_SUCCESS;
}

typedef struct level_alias_hash_state
{
	unsigned int bucket;
	hashtab_node_t *node;
	hashtab_t *table;
	uint32_t val;
} level_alias_hash_state_t;

static int hash_state_next_level_alias(qpol_iterator_t * iter)
{
	level_alias_hash_state_t *hs = NULL;
	level_datum_t *datum = NULL;

	if (iter == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	hs = (level_alias_hash_state_t *) qpol_iterator_state(iter);
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
		datum = hs->node ? (level_datum_t *) hs->node->datum : NULL;
	} while (datum != NULL && (datum->level->sens != hs->val || !datum->isalias));

	return STATUS_SUCCESS;
}

static void *hash_state_get_cur_alias(const qpol_iterator_t * iter)
{
	level_alias_hash_state_t *hs = NULL;

	if (iter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	hs = (level_alias_hash_state_t *) qpol_iterator_state(iter);
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

static size_t hash_state_level_alias_size(const qpol_iterator_t * iter)
{
	level_alias_hash_state_t *hs = NULL;
	hashtab_node_t *tmp_node;
	level_datum_t *tmp_lvl_datum;
	uint32_t tmp_bucket = 0;
	size_t count = 0;
	if (iter == NULL || qpol_iterator_state(iter) == NULL) {
		errno = EINVAL;
		return 0;
	}
	hs = (level_alias_hash_state_t *) qpol_iterator_state(iter);
	if (!hs) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	for (tmp_bucket = 0; tmp_bucket < (*(hs->table))->size; tmp_bucket++) {
		for (tmp_node = (*(hs->table))->htable[tmp_bucket]; tmp_node; tmp_node = tmp_node->next) {
			tmp_lvl_datum = tmp_node ? tmp_node->datum : NULL;
			if (tmp_lvl_datum) {
				if (tmp_lvl_datum->isalias && tmp_lvl_datum->level->sens == hs->val)
					count++;
			}
		}
	}
	return count;
}

int qpol_level_get_alias_iter(const qpol_policy_t * policy, const qpol_level_t * datum, qpol_iterator_t ** aliases)
{
	level_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;
	int error;
	level_alias_hash_state_t *hs = NULL;

	if (policy == NULL || datum == NULL || aliases == NULL) {
		if (aliases != NULL)
			*aliases = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_datum = (level_datum_t *) datum;

	hs = calloc(1, sizeof(level_alias_hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &db->p_levels.table;
	hs->node = (*(hs->table))->htable[0];
	hs->val = internal_datum->level->sens;

	if (qpol_iterator_create(policy, (void *)hs, hash_state_get_cur_alias,
				 hash_state_next_level_alias, hash_state_end, hash_state_level_alias_size, free, aliases)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL || !((level_datum_t *) hs->node->datum)->isalias
	    || ((level_datum_t *) (hs->node->datum))->level->sens != hs->val)
		hash_state_next_level_alias(*aliases);

	return STATUS_SUCCESS;
}

/* cat */
int qpol_policy_get_cat_by_name(const qpol_policy_t * policy, const char *name, const qpol_cat_t ** datum)
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
	internal_datum = hashtab_search(db->p_cats.table, (const hashtab_key_t)name);
	if (internal_datum == NULL) {
		*datum = NULL;
		ERR(policy, "could not find datum for cat %s", name);
		errno = ENOENT;
		return STATUS_ERR;
	}
	*datum = (qpol_cat_t *) internal_datum;

	return STATUS_SUCCESS;
}

int qpol_policy_get_cat_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
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
	hs->table = &db->p_cats.table;
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

int qpol_cat_get_value(const qpol_policy_t * policy, const qpol_cat_t * datum, uint32_t * value)
{
	cat_datum_t *internal_datum = NULL;

	if (policy == NULL || datum == NULL || value == NULL) {
		if (value != NULL)
			*value = 0;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (cat_datum_t *) datum;
	*value = internal_datum->s.value;

	return STATUS_SUCCESS;
}

int qpol_cat_get_isalias(const qpol_policy_t * policy, const qpol_cat_t * datum, unsigned char *isalias)
{
	cat_datum_t *internal_datum;

	if (policy == NULL || datum == NULL || isalias == NULL) {
		if (isalias != NULL)
			*isalias = 0;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (cat_datum_t *) datum;
	*isalias = internal_datum->isalias;

	return STATUS_SUCCESS;
}

int qpol_cat_get_name(const qpol_policy_t * policy, const qpol_cat_t * datum, const char **name)
{
	cat_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;

	if (policy == NULL || datum == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_datum = (cat_datum_t *) datum;

	*name = db->p_cat_val_to_name[internal_datum->s.value - 1];

	return STATUS_SUCCESS;
}

static int hash_state_next_cat_alias(qpol_iterator_t * iter)
{
	/* using level alias state datum since data needed is identical */
	level_alias_hash_state_t *hs = NULL;
	cat_datum_t *datum = NULL;

	if (iter == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	hs = (level_alias_hash_state_t *) qpol_iterator_state(iter);
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
		datum = hs->node ? (cat_datum_t *) hs->node->datum : NULL;
	} while (datum != NULL && (datum->s.value != hs->val || !datum->isalias));

	return STATUS_SUCCESS;
}

static size_t hash_state_cat_alias_size(const qpol_iterator_t * iter)
{
	level_alias_hash_state_t *hs = NULL;
	hashtab_node_t *tmp_node;
	cat_datum_t *tmp_cat_datum;
	uint32_t tmp_bucket = 0;
	size_t count = 0;
	if (iter == NULL || qpol_iterator_state(iter) == NULL) {
		errno = EINVAL;
		return 0;
	}
	hs = (level_alias_hash_state_t *) qpol_iterator_state(iter);
	if (!hs) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	for (tmp_bucket = 0; tmp_bucket < (*(hs->table))->size; tmp_bucket++) {
		for (tmp_node = (*(hs->table))->htable[tmp_bucket]; tmp_node; tmp_node = tmp_node->next) {
			tmp_cat_datum = tmp_node ? tmp_node->datum : NULL;
			if (tmp_cat_datum) {
				if (tmp_cat_datum->isalias && tmp_cat_datum->s.value == hs->val)
					count++;
			}
		}
	}
	return count;
}

int qpol_cat_get_alias_iter(const qpol_policy_t * policy, const qpol_cat_t * datum, qpol_iterator_t ** aliases)
{
	cat_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;
	int error;
	level_alias_hash_state_t *hs = NULL;

	if (policy == NULL || datum == NULL || aliases == NULL) {
		if (aliases != NULL)
			*aliases = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	internal_datum = (cat_datum_t *) datum;

	hs = calloc(1, sizeof(level_alias_hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &db->p_cats.table;
	hs->node = (*(hs->table))->htable[0];
	hs->val = internal_datum->s.value;

	if (qpol_iterator_create(policy, (void *)hs, hash_state_get_cur_alias,
				 hash_state_next_cat_alias, hash_state_end, hash_state_cat_alias_size, free, aliases)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL || ((cat_datum_t *) (hs->node->datum))->s.value != hs->val)
		hash_state_next_cat_alias(*aliases);

	return STATUS_SUCCESS;
}

/* mls range */
int qpol_mls_range_get_low_level(const qpol_policy_t * policy, const qpol_mls_range_t * range, const qpol_mls_level_t ** level)
{
	mls_range_t *internal_range = NULL;

	if (policy == NULL || range == NULL || level == NULL) {
		if (level != NULL)
			*level = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_range = (mls_range_t *) range;
	*level = (qpol_mls_level_t *) & (internal_range->level[0]);

	return STATUS_SUCCESS;
}

int qpol_mls_range_get_high_level(const qpol_policy_t * policy, const qpol_mls_range_t * range, const qpol_mls_level_t ** level)
{
	mls_range_t *internal_range = NULL;

	if (policy == NULL || range == NULL || level == NULL) {
		if (level != NULL)
			*level = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_range = (mls_range_t *) range;
	*level = (qpol_mls_level_t *) & (internal_range->level[1]);

	return STATUS_SUCCESS;
}

/* mls_level */
int qpol_mls_level_get_sens_name(const qpol_policy_t * policy, const qpol_mls_level_t * level, const char **name)
{
	policydb_t *db = NULL;
	mls_level_t *internal_level = NULL;

	if (policy == NULL || level == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_level = (mls_level_t *) level;
	db = &policy->p->p;

	*name = db->p_sens_val_to_name[internal_level->sens - 1];

	return STATUS_SUCCESS;
}

int qpol_mls_level_get_cat_iter(const qpol_policy_t * policy, const qpol_mls_level_t * level, qpol_iterator_t ** cats)
{
	mls_level_t *internal_level = NULL;
	ebitmap_state_t *es = NULL;
	int error = 0;

	if (policy == NULL || level == NULL || cats == NULL) {
		if (cats != NULL)
			*cats = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_level = (mls_level_t *) level;

	es = calloc(1, sizeof(ebitmap_state_t));
	if (es == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}

	es->bmap = &(internal_level->cat);
	es->cur = es->bmap->node ? es->bmap->node->startbit : 0;

	if (qpol_iterator_create(policy, es, ebitmap_state_get_cur_cat,
				 ebitmap_state_next, ebitmap_state_end, ebitmap_state_size, free, cats)) {
		free(es);
		return STATUS_ERR;
	}

	if (es->bmap->node && !ebitmap_get_bit(es->bmap, es->cur))
		ebitmap_state_next(*cats);

	return STATUS_SUCCESS;
}
