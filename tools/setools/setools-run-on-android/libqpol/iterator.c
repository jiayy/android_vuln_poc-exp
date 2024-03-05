/**
 * @file
 * Contains the implementation of the qpol_iterator API, both
 * public and private, for returning lists of components and rules
 * from the policy database.
 *
 * @author Kevin Carr kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang jtang@tresys.com
 *
 * Copyright (C) 2006-2008 Tresys Technology, LLC
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

#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/mls_query.h>

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/polcaps.h>
#include <sepol/policydb/util.h>
#include <sepol/policydb.h>

#include "qpol_internal.h"
#include "iterator_internal.h"

/**
 * Declaration of qpol_iterator, an arbitrary valued policy component
 * iterator used to return lists of components.
 *
 */
struct qpol_iterator
{
	policydb_t *policy;
	void *state;
	void *(*get_cur) (const qpol_iterator_t * iter);
	int (*next) (qpol_iterator_t * iter);
	int (*end) (const qpol_iterator_t * iter);
	 size_t(*size) (const qpol_iterator_t * iter);
	void (*free_fn) (void *x);
};

/**
 * The number of buckets in sepol's av tables was statically set in
 * libsepol < 2.0.20.  With libsepol 2.0.20, this size was dynamically
 * calculated based upon the number of rules.
 */
static uint32_t iterator_get_avtab_size(const avtab_t * avtab)
{
#ifdef SEPOL_DYNAMIC_AVTAB
	return avtab->nslot;
#else
	return AVTAB_SIZE;
#endif
}

int qpol_iterator_create(const qpol_policy_t * policy, void *state,
			 void *(*get_cur) (const qpol_iterator_t * iter),
			 int (*next) (qpol_iterator_t * iter),
			 int (*end) (const qpol_iterator_t * iter),
			 size_t(*size) (const qpol_iterator_t * iter), void (*free_fn) (void *x), qpol_iterator_t ** iter)
{
	int error = 0;

	if (iter != NULL)
		*iter = NULL;

	if (policy == NULL || state == NULL || iter == NULL || get_cur == NULL || next == NULL || end == NULL || size == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*iter = calloc(1, sizeof(struct qpol_iterator));
	if (*iter == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}

	(*iter)->policy = &policy->p->p;
	(*iter)->state = state;
	(*iter)->get_cur = get_cur;
	(*iter)->next = next;
	(*iter)->end = end;
	(*iter)->size = size;
	(*iter)->free_fn = free_fn;

	return STATUS_SUCCESS;
}

void *qpol_iterator_state(const qpol_iterator_t * iter)
{
	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return iter->state;
}

const policydb_t *qpol_iterator_policy(const qpol_iterator_t * iter)
{
	if (iter == NULL || iter->policy == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return iter->policy;
}

void *hash_state_get_cur(const qpol_iterator_t * iter)
{
	hash_state_t *hs = NULL;

	if (iter == NULL || iter->state == NULL || hash_state_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	hs = (hash_state_t *) iter->state;

	return hs->node->datum;
}

void *hash_state_get_cur_key(const qpol_iterator_t * iter)
{
	hash_state_t *hs = NULL;

	if (iter == NULL || iter->state == NULL || hash_state_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	hs = (hash_state_t *) iter->state;

	return hs->node->key;
}

void *ocon_state_get_cur(const qpol_iterator_t * iter)
{
	ocon_state_t *os = NULL;

	if (iter == NULL || iter->state == NULL || ocon_state_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	os = (ocon_state_t *) iter->state;

	return os->cur;
}

void *avtab_state_get_cur(const qpol_iterator_t * iter)
{
	avtab_state_t *state;

	if (iter == NULL || iter->state == NULL || avtab_state_end(iter)) {
		errno = EINVAL;
		return NULL;
	}
	state = (avtab_state_t *) iter->state;
	return state->node;
}

int hash_state_next(qpol_iterator_t * iter)
{
	hash_state_t *hs = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	hs = (hash_state_t *) iter->state;

	if (hs->table == NULL || *(hs->table) == NULL || hs->bucket >= (*(hs->table))->size) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	if (hs->node != NULL && hs->node->next != NULL) {
		hs->node = hs->node->next;
	} else {
		do {
			hs->bucket++;
			if (hs->bucket < (*(hs->table))->size) {
				hs->node = (*(hs->table))->htable[hs->bucket];
			} else {
				hs->node = NULL;
			}
		} while (hs->bucket < (*(hs->table))->size && hs->node == NULL);
	}

	return STATUS_SUCCESS;
}

int ebitmap_state_next(qpol_iterator_t * iter)
{
	ebitmap_state_t *es = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	es = (ebitmap_state_t *) iter->state;

	if (es->cur >= es->bmap->highbit) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	do {
		es->cur++;
	} while (es->cur < es->bmap->highbit && !ebitmap_get_bit(es->bmap, es->cur));

	return STATUS_SUCCESS;
}

int ocon_state_next(qpol_iterator_t * iter)
{
	ocon_state_t *os = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	os = (ocon_state_t *) iter->state;

	if (os->cur == NULL) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	os->cur = os->cur->next;

	return STATUS_SUCCESS;
}

int avtab_state_next(qpol_iterator_t * iter)
{
	avtab_t *avtab;
	avtab_state_t *state;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	state = iter->state;
	avtab = (state->which == QPOL_AVTAB_STATE_AV ? state->ucond_tab : state->cond_tab);

	if ((!avtab->htable || state->bucket >= iterator_get_avtab_size(avtab)) && state->which == QPOL_AVTAB_STATE_COND) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	do {
		if (state->node != NULL && state->node->next != NULL) {
			state->node = state->node->next;
		} else {
			/* find the next bucket */
			do {
				state->bucket++;
				if (!avtab->htable || state->bucket >= iterator_get_avtab_size(avtab)) {
					if (state->which == QPOL_AVTAB_STATE_AV) {
						state->bucket = 0;
						avtab = state->cond_tab;
						state->which = QPOL_AVTAB_STATE_COND;
					} else {
						state->node = NULL;
						break;
					}
				}
				if (avtab->htable && avtab->htable[state->bucket] != NULL) {
					state->node = avtab->htable[state->bucket];
					break;
				}
			} while (avtab->htable && state->bucket < iterator_get_avtab_size(avtab));
		}
	} while (avtab->htable && state->bucket < iterator_get_avtab_size(avtab) &&
		 state->node ? !(state->rule_type_mask & state->node->key.specified) : 0);

	return STATUS_SUCCESS;
}

int hash_state_end(const qpol_iterator_t * iter)
{
	hash_state_t *hs = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	hs = (hash_state_t *) iter->state;

	if (hs->table == NULL || *(hs->table) == NULL || (*(hs->table))->nel == 0 || hs->bucket >= (*(hs->table))->size)
		return 1;

	return 0;
}

int ebitmap_state_end(const qpol_iterator_t * iter)
{
	ebitmap_state_t *es = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	es = (ebitmap_state_t *) iter->state;

	if (es->cur >= es->bmap->highbit)
		return 1;

	return 0;
}

int ocon_state_end(const qpol_iterator_t * iter)
{
	ocon_state_t *os = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	os = (ocon_state_t *) iter->state;

	if (os->cur == NULL)
		return 1;

	return 0;
}

int avtab_state_end(const qpol_iterator_t * iter)
{
	avtab_state_t *state;
	avtab_t *avtab;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	state = iter->state;
	avtab = (state->which == QPOL_AVTAB_STATE_AV ? state->ucond_tab : state->cond_tab);
	if ((!avtab->htable || state->bucket >= iterator_get_avtab_size(avtab)) && state->which == QPOL_AVTAB_STATE_COND)
		return 1;
	return 0;
}

size_t hash_state_size(const qpol_iterator_t * iter)
{
	hash_state_t *hs = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return 0;
	}

	hs = (hash_state_t *) iter->state;

	return (*(hs->table))->nel;
}

size_t ebitmap_state_size(const qpol_iterator_t * iter)
{
	ebitmap_state_t *es = NULL;
	size_t count = 0, bit = 0;
	ebitmap_node_t *node = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return 0;
	}

	es = (ebitmap_state_t *) iter->state;

	ebitmap_for_each_bit(es->bmap, node, bit) {
		count += ebitmap_get_bit(es->bmap, bit);
	}

	return count;
}

size_t ocon_state_size(const qpol_iterator_t * iter)
{
	ocon_state_t *os = NULL;
	size_t count = 0;
	ocontext_t *ocon = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return 0;
	}

	os = (ocon_state_t *) iter->state;

	for (ocon = os->head; ocon; ocon = ocon->next)
		count++;

	return count;
}

size_t avtab_state_size(const qpol_iterator_t * iter)
{
	avtab_state_t *state;
	avtab_t *avtab;
	size_t count = 0;
	avtab_ptr_t node = NULL;
	uint32_t bucket = 0;

	if (iter == NULL || iter->state == NULL || iter->policy == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	state = iter->state;
	avtab = state->ucond_tab;

	for (bucket = 0; avtab->htable && bucket < iterator_get_avtab_size(avtab); bucket++) {
		for (node = avtab->htable[bucket]; node; node = node->next) {
			if (node->key.specified & state->rule_type_mask)
				count++;
		}
	}

	avtab = state->cond_tab;

	for (bucket = 0; avtab->htable && bucket < iterator_get_avtab_size(avtab); bucket++) {
		for (node = avtab->htable[bucket]; node; node = node->next) {
			if (node->key.specified & state->rule_type_mask)
				count++;
		}
	}

	return count;
}

void qpol_iterator_destroy(qpol_iterator_t ** iter)
{
	if (iter == NULL || *iter == NULL)
		return;

	if ((*iter)->free_fn)
		(*iter)->free_fn((*iter)->state);

	free(*iter);
	*iter = NULL;
}

int qpol_iterator_get_item(const qpol_iterator_t * iter, void **item)
{
	if (item != NULL)
		*item = NULL;

	if (iter == NULL || iter->get_cur == NULL || item == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	*item = iter->get_cur(iter);
	if (*item == NULL)
		return STATUS_ERR;

	return STATUS_SUCCESS;
}

int qpol_iterator_next(qpol_iterator_t * iter)
{
	if (iter == NULL || iter->next == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return iter->next(iter);
}

int qpol_iterator_end(const qpol_iterator_t * iter)
{
	if (iter == NULL || iter->end == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return iter->end(iter);
}

int qpol_iterator_get_size(const qpol_iterator_t * iter, size_t * size)
{
	if (size != NULL)
		*size = 0;

	if (iter == NULL || size == NULL || iter->size == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	*size = iter->size(iter);

	return STATUS_SUCCESS;
}

void *ebitmap_state_get_cur_type(const qpol_iterator_t * iter)
{
	ebitmap_state_t *es = NULL;
	const policydb_t *db = NULL;

	if (iter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	es = qpol_iterator_state(iter);
	if (es == NULL) {
		errno = EINVAL;
		return NULL;
	}
	db = qpol_iterator_policy(iter);
	if (db == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return db->type_val_to_struct[es->cur];
}

void *ebitmap_state_get_cur_role(const qpol_iterator_t * iter)
{
	ebitmap_state_t *es = NULL;
	const policydb_t *db = NULL;

	if (iter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	es = qpol_iterator_state(iter);
	if (es == NULL) {
		errno = EINVAL;
		return NULL;
	}
	db = qpol_iterator_policy(iter);
	if (db == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return db->role_val_to_struct[es->cur];
}

void *ebitmap_state_get_cur_cat(const qpol_iterator_t * iter)
{
	ebitmap_state_t *es = NULL;
	const policydb_t *db = NULL;
	const qpol_cat_t *cat = NULL;
	sepol_policydb_t sp;
	qpol_policy_t qp;

	if (iter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	es = qpol_iterator_state(iter);
	if (es == NULL) {
		errno = EINVAL;
		return NULL;
	}
	db = qpol_iterator_policy(iter);
	if (db == NULL) {
		errno = EINVAL;
		return NULL;
	}

	/* shallow copy is safe here */
	sp.p = *db;
	qp.p = &sp;
	qp.fn = NULL;

	qpol_policy_get_cat_by_name(&qp, db->p_cat_val_to_name[es->cur], &cat);

	/* There is no val_to_struct for categories; this requires that qpol
	 * search for the struct, but it can't be returned as const here so
	 * cast it to void* explicitly. */
	return (void *)cat;
}

void *ebitmap_state_get_cur_permissive(const qpol_iterator_t * iter)
{
	ebitmap_state_t *es = NULL;
	const policydb_t *db = NULL;

	if (iter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	es = qpol_iterator_state(iter);
	if (es == NULL) {
		errno = EINVAL;
		return NULL;
	}
	db = qpol_iterator_policy(iter);
	if (db == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return db->type_val_to_struct[es->cur - 1];
}

void *ebitmap_state_get_cur_polcap(const qpol_iterator_t * iter)
{
	ebitmap_state_t *es = NULL;
	const policydb_t *db = NULL;

	if (iter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	es = qpol_iterator_state(iter);
	if (es == NULL) {
		errno = EINVAL;
		return NULL;
	}
	db = qpol_iterator_policy(iter);
	if (db == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return (void*)sepol_polcap_getname(es->cur);
}

void ebitmap_state_destroy(void *es)
{
	ebitmap_state_t *ies = (ebitmap_state_t *) es;

	if (!es)
		return;

	ebitmap_destroy(ies->bmap);
	free(ies->bmap);
	free(ies);
}

int perm_state_end(const qpol_iterator_t * iter)
{
	perm_state_t *ps = NULL;
	const policydb_t *db = NULL;
	unsigned int perm_max = 0;

	if (iter == NULL || (ps = qpol_iterator_state(iter)) == NULL || (db = qpol_iterator_policy(iter)) == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	/* permission max is number of permissions in the class which includes
	 * the number of permissions in its common if it inherits one */
	perm_max = db->class_val_to_struct[ps->obj_class_val - 1]->permissions.nprim;
	if (perm_max > 32) {
		errno = EDOM;	       /* perms set mask is a uint32_t cannot use more than 32 bits */
		return STATUS_ERR;
	}

	if (!(ps->perm_set) || ps->cur >= perm_max)
		return 1;

	return 0;
}

void *perm_state_get_cur(const qpol_iterator_t * iter)
{
	const policydb_t *db = NULL;
	class_datum_t *obj_class = NULL;
	common_datum_t *comm = NULL;
	perm_state_t *ps = NULL;
	unsigned int perm_max = 0;
	char *tmp = NULL;

	if (iter == NULL || (db = qpol_iterator_policy(iter)) == NULL ||
	    (ps = (perm_state_t *) qpol_iterator_state(iter)) == NULL || perm_state_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	obj_class = db->class_val_to_struct[ps->obj_class_val - 1];
	comm = obj_class->comdatum;

	/* permission max is number of permissions in the class which includes
	 * the number of permissions in its common if it inherits one */
	perm_max = obj_class->permissions.nprim;
	if (perm_max > 32) {
		errno = EDOM;	       /* perms set mask is a uint32_t cannot use more than 32 bits */
		return NULL;
	}
	if (ps->cur >= perm_max) {
		errno = ERANGE;
		return NULL;
	}
	if (!(ps->perm_set & 1 << (ps->cur))) {	/* perm bit not set? */
		errno = EINVAL;
		return NULL;
	}

	/* explicit const_cast for sepol */
	tmp = sepol_av_to_string((policydb_t *) db, ps->obj_class_val, (sepol_access_vector_t) 1 << (ps->cur));
	if (tmp) {
		tmp++;		       /*sepol_av_to_string prepends a ' ' to the name */
		return strdup(tmp);
	} else {
		errno = EINVAL;
		return NULL;
	}
}

int perm_state_next(qpol_iterator_t * iter)
{
	perm_state_t *ps = NULL;
	const policydb_t *db = NULL;
	unsigned int perm_max = 0;

	if (iter == NULL || (ps = qpol_iterator_state(iter)) == NULL ||
	    (db = qpol_iterator_policy(iter)) == NULL || perm_state_end(iter)) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	/* permission max is number of permissions in the class which includes
	 * the number of permissions in its common if it inherits one */
	perm_max = db->class_val_to_struct[ps->obj_class_val - 1]->permissions.nprim;
	if (perm_max > 32) {
		errno = EDOM;	       /* perms set mask is a uint32_t cannot use more than 32 bits */
		return STATUS_ERR;
	}

	if (ps->cur >= perm_max) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	do {
		ps->cur++;
	} while (ps->cur < perm_max && !(ps->perm_set & 1 << (ps->cur)));

	return STATUS_SUCCESS;
}

size_t perm_state_size(const qpol_iterator_t * iter)
{
	perm_state_t *ps = NULL;
	const policydb_t *db = NULL;
	unsigned int perm_max = 0;
	size_t i, count = 0;

	if (iter == NULL || (ps = qpol_iterator_state(iter)) == NULL ||
	    (db = qpol_iterator_policy(iter)) == NULL || perm_state_end(iter)) {
		errno = EINVAL;
		return 0;	       /* as a size_t 0 is error */
	}

	/* permission max is number of permissions in the class which includes
	 * the number of permissions in its common if it inherits one */
	perm_max = db->class_val_to_struct[ps->obj_class_val - 1]->permissions.nprim;
	if (perm_max > 32) {
		errno = EDOM;	       /* perms set mask is a uint32_t cannot use more than 32 bits */
		return 0;	       /* as a size_t 0 is error */
	}

	for (i = 0; i < perm_max; i++) {
		if (ps->perm_set & 1 << i)
			count++;
	}

	return count;
}
