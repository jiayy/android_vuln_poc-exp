/**
 * @file
 * Declaration of the internal interface for 
 * qpol_iterator, an arbitrary valued policy component
 * iterator used to return lists of components.
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

#ifndef QPOL_ITERATOR_INTERNAL_H
#define QPOL_ITERATOR_INTERNAL_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/avtab.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <stddef.h>

	typedef struct hash_state
	{
		unsigned int bucket;
		hashtab_node_t *node;
		hashtab_t *table;
	} hash_state_t;

	typedef struct ebitmap_state
	{
		ebitmap_t *bmap;
		size_t cur;
	} ebitmap_state_t;

	typedef struct ocon_state
	{
		ocontext_t *head;
		ocontext_t *cur;
	} ocon_state_t;

	typedef struct perm_state
	{
		uint32_t perm_set;
		uint32_t obj_class_val;
		uint8_t cur;
	} perm_state_t;

	typedef struct avtab_state
	{
		uint32_t rule_type_mask;
		avtab_t *ucond_tab;
		avtab_t *cond_tab;
		uint32_t bucket;
		avtab_ptr_t node;
#define QPOL_AVTAB_STATE_AV   0
#define QPOL_AVTAB_STATE_COND 1
		unsigned which;
	} avtab_state_t;

	int qpol_iterator_create(const qpol_policy_t * policy, void *state,
				 void *(*get_cur) (const qpol_iterator_t * iter),
				 int (*next) (qpol_iterator_t * iter),
				 int (*end) (const qpol_iterator_t * iter),
				 size_t(*size) (const qpol_iterator_t * iter), void (*free_fn) (void *x), qpol_iterator_t ** iter);

	void *qpol_iterator_state(const qpol_iterator_t * iter);
	const policydb_t *qpol_iterator_policy(const qpol_iterator_t * iter);

	void *hash_state_get_cur(const qpol_iterator_t * iter);
	void *hash_state_get_cur_key(const qpol_iterator_t * iter);
	void *ebitmap_state_get_cur_type(const qpol_iterator_t * iter);
	void *ebitmap_state_get_cur_role(const qpol_iterator_t * iter);
	void *ebitmap_state_get_cur_cat(const qpol_iterator_t * iter);
	void *ebitmap_state_get_cur_permissive(const qpol_iterator_t * iter);
	void *ebitmap_state_get_cur_polcap(const qpol_iterator_t * iter);
	void *ocon_state_get_cur(const qpol_iterator_t * iter);
	void *perm_state_get_cur(const qpol_iterator_t * iter);
	void *avtab_state_get_cur(const qpol_iterator_t * iter);

	int hash_state_next(qpol_iterator_t * iter);
	int ebitmap_state_next(qpol_iterator_t * iter);
	int ocon_state_next(qpol_iterator_t * iter);
	int perm_state_next(qpol_iterator_t * iter);
	int avtab_state_next(qpol_iterator_t * iter);

	int hash_state_end(const qpol_iterator_t * iter);
	int ebitmap_state_end(const qpol_iterator_t * iter);
	int ocon_state_end(const qpol_iterator_t * iter);
	int perm_state_end(const qpol_iterator_t * iter);
	int avtab_state_end(const qpol_iterator_t * iter);

	size_t hash_state_size(const qpol_iterator_t * iter);
	size_t ebitmap_state_size(const qpol_iterator_t * iter);
	size_t ocon_state_size(const qpol_iterator_t * iter);
	size_t perm_state_size(const qpol_iterator_t * iter);
	size_t avtab_state_size(const qpol_iterator_t * iter);

	void ebitmap_state_destroy(void *es);
#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_ITERATOR_INTERNAL_H */
