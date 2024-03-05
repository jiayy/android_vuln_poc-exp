 /**
 *  @file
 *  Implementation for the public interface for searching and iterating over avrules.
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

#include "iterator_internal.h"
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/avrule_query.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/util.h>
#include <stdlib.h>
#include "qpol_internal.h"

int qpol_policy_get_avrule_iter(const qpol_policy_t * policy, uint32_t rule_type_mask, qpol_iterator_t ** iter)
{
	policydb_t *db;
	avtab_state_t *state;

	if (iter) {
		*iter = NULL;
	}
	if (policy == NULL || iter == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

#if 1	// Seems to make sediff/sediffx work better without breaking things
	if (!qpol_policy_has_capability(policy, QPOL_CAP_RULES_LOADED)) {
		ERR(policy, "%s", "Cannot get avrules: Rules not loaded");
		errno = ENOTSUP;
		return STATUS_ERR;
	}
#endif

	if ((rule_type_mask & QPOL_RULE_NEVERALLOW) && !qpol_policy_has_capability(policy, QPOL_CAP_NEVERALLOW)) {
		ERR(policy, "%s", "Cannot get avrules: Neverallow rules requested but not available. Skipping neverallow rules...");
		rule_type_mask &= ~(uint32_t)QPOL_RULE_NEVERALLOW;
	}

	db = &policy->p->p;

	state = calloc(1, sizeof(avtab_state_t));
	if (state == NULL) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return STATUS_ERR;
	}
	state->ucond_tab = &db->te_avtab;
	state->cond_tab = &db->te_cond_avtab;
	state->rule_type_mask = rule_type_mask;
	state->node = db->te_avtab.htable[0];

	if (qpol_iterator_create
	    (policy, state, avtab_state_get_cur, avtab_state_next, avtab_state_end, avtab_state_size, free, iter)) {
		free(state);
		return STATUS_ERR;
	}
	if (state->node == NULL || !(state->node->key.specified & state->rule_type_mask)) {
		avtab_state_next(*iter);
	}
	return STATUS_SUCCESS;
}

int qpol_avrule_get_source_type(const qpol_policy_t * policy, const qpol_avrule_t * rule, const qpol_type_t ** source)
{
	policydb_t *db = NULL;
	avtab_ptr_t avrule = NULL;

	if (source) {
		*source = NULL;
	}

	if (!policy || !rule || !source) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	avrule = (avtab_ptr_t) rule;

	*source = (qpol_type_t *) db->type_val_to_struct[avrule->key.source_type - 1];

	return STATUS_SUCCESS;
}

int qpol_avrule_get_target_type(const qpol_policy_t * policy, const qpol_avrule_t * rule, const qpol_type_t ** target)
{
	policydb_t *db = NULL;
	avtab_ptr_t avrule = NULL;

	if (target) {
		*target = NULL;
	}

	if (!policy || !rule || !target) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	avrule = (avtab_ptr_t) rule;

	*target = (qpol_type_t *) db->type_val_to_struct[avrule->key.target_type - 1];

	return STATUS_SUCCESS;
}

int qpol_avrule_get_object_class(const qpol_policy_t * policy, const qpol_avrule_t * rule, const qpol_class_t ** obj_class)
{
	policydb_t *db = NULL;
	avtab_ptr_t avrule = NULL;

	if (obj_class) {
		*obj_class = NULL;
	}

	if (!policy || !rule || !obj_class) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	avrule = (avtab_ptr_t) rule;

	*obj_class = (qpol_class_t *) db->class_val_to_struct[avrule->key.target_class - 1];

	return STATUS_SUCCESS;
}

int qpol_avrule_get_perm_iter(const qpol_policy_t * policy, const qpol_avrule_t * rule, qpol_iterator_t ** perms)
{
	policydb_t *db = NULL;
	avtab_ptr_t avrule = NULL;
	perm_state_t *ps = NULL;

	if (perms) {
		*perms = NULL;
	}

	if (!policy || !rule || !perms) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	avrule = (avtab_ptr_t) rule;
	ps = calloc(1, sizeof(perm_state_t));
	if (!ps) {
		return STATUS_ERR;
	}
	if (avrule->key.specified & QPOL_RULE_DONTAUDIT) {
		ps->perm_set = ~(avrule->datum.data);	/* stored as auditdeny flip the bits */
	} else {
		ps->perm_set = avrule->datum.data;
	}
	ps->obj_class_val = avrule->key.target_class;

	if (qpol_iterator_create(policy, (void *)ps, perm_state_get_cur,
				 perm_state_next, perm_state_end, perm_state_size, free, perms)) {
		return STATUS_ERR;
	}

	if (!(ps->perm_set & 1))       /* defaults to bit 0, if off: advance */
		perm_state_next(*perms);

	return STATUS_SUCCESS;
}

int qpol_avrule_get_rule_type(const qpol_policy_t * policy, const qpol_avrule_t * rule, uint32_t * rule_type)
{
	policydb_t *db = NULL;
	avtab_ptr_t avrule = NULL;

	if (rule_type) {
		*rule_type = 0;
	}

	if (!policy || !rule || !rule_type) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	avrule = (avtab_ptr_t) rule;

	*rule_type =
		(avrule->key.specified & (QPOL_RULE_ALLOW | QPOL_RULE_NEVERALLOW | QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT));

	return STATUS_SUCCESS;
}

int qpol_avrule_get_cond(const qpol_policy_t * policy, const qpol_avrule_t * rule, const qpol_cond_t ** cond)
{
	avtab_ptr_t avrule = NULL;

	if (cond) {
		*cond = NULL;
	}

	if (!policy || !rule || !cond) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	avrule = (avtab_ptr_t) rule;

	*cond = (qpol_cond_t *) avrule->parse_context;

	return STATUS_SUCCESS;
}

int qpol_avrule_get_is_enabled(const qpol_policy_t * policy, const qpol_avrule_t * rule, uint32_t * is_enabled)
{
	avtab_ptr_t avrule = NULL;

	if (is_enabled) {
		*is_enabled = 0;
	}

	if (!policy || !rule || !is_enabled) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	avrule = (avtab_ptr_t) rule;

	*is_enabled = ((avrule->merged & QPOL_COND_RULE_ENABLED) ? 1 : 0);

	return STATUS_SUCCESS;
}

int qpol_avrule_get_which_list(const qpol_policy_t * policy, const qpol_avrule_t * rule, uint32_t * which_list)
{
	avtab_ptr_t avrule = NULL;

	if (which_list) {
		*which_list = 0;
	}

	if (!policy || !rule || !which_list) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	avrule = (avtab_ptr_t) rule;

	if (!avrule->parse_context) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*which_list = ((avrule->merged & QPOL_COND_RULE_LIST) ? 1 : 0);

	return STATUS_SUCCESS;
}
