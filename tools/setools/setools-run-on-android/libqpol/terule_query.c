/**
 *  @file
 *  Implementation for the public interface for searching and iterating over type rules.
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
#include <qpol/terule_query.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/util.h>
#include <stdlib.h>
#include "qpol_internal.h"

int qpol_policy_get_terule_iter(const qpol_policy_t * policy, uint32_t rule_type_mask, qpol_iterator_t ** iter)
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
		ERR(policy, "%s", "Cannot get terules: Rules not loaded");
		errno = ENOTSUP;
		return STATUS_ERR;
	}
#endif

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

int qpol_terule_get_source_type(const qpol_policy_t * policy, const qpol_terule_t * rule, const qpol_type_t ** source)
{
	policydb_t *db = NULL;
	avtab_ptr_t terule = NULL;

	if (source) {
		*source = NULL;
	}

	if (!policy || !rule || !source) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	terule = (avtab_ptr_t) rule;

	*source = (qpol_type_t *) db->type_val_to_struct[terule->key.source_type - 1];

	return STATUS_SUCCESS;
}

int qpol_terule_get_target_type(const qpol_policy_t * policy, const qpol_terule_t * rule, const qpol_type_t ** target)
{
	policydb_t *db = NULL;
	avtab_ptr_t terule = NULL;

	if (target) {
		*target = NULL;
	}

	if (!policy || !rule || !target) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	terule = (avtab_ptr_t) rule;

	*target = (qpol_type_t *) db->type_val_to_struct[terule->key.target_type - 1];

	return STATUS_SUCCESS;
}

int qpol_terule_get_object_class(const qpol_policy_t * policy, const qpol_terule_t * rule, const qpol_class_t ** obj_class)
{
	policydb_t *db = NULL;
	avtab_ptr_t terule = NULL;

	if (obj_class) {
		*obj_class = NULL;
	}

	if (!policy || !rule || !obj_class) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	terule = (avtab_ptr_t) rule;

	*obj_class = (qpol_class_t *) db->class_val_to_struct[terule->key.target_class - 1];

	return STATUS_SUCCESS;
}

int qpol_terule_get_default_type(const qpol_policy_t * policy, const qpol_terule_t * rule, const qpol_type_t ** dflt)
{
	policydb_t *db = NULL;
	avtab_ptr_t terule = NULL;

	if (dflt) {
		*dflt = NULL;
	}

	if (!policy || !rule || !dflt) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	terule = (avtab_ptr_t) rule;

	*dflt = (qpol_type_t *) db->type_val_to_struct[terule->datum.data - 1];

	return STATUS_SUCCESS;
}

int qpol_terule_get_rule_type(const qpol_policy_t * policy, const qpol_terule_t * rule, uint32_t * rule_type)
{
	policydb_t *db = NULL;
	avtab_ptr_t terule = NULL;

	if (rule_type) {
		*rule_type = 0;
	}

	if (!policy || !rule || !rule_type) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	terule = (avtab_ptr_t) rule;

	*rule_type = (terule->key.specified & (QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER));

	return STATUS_SUCCESS;
}

int qpol_terule_get_cond(const qpol_policy_t * policy, const qpol_terule_t * rule, const qpol_cond_t ** cond)
{
	avtab_ptr_t terule = NULL;

	if (cond) {
		*cond = NULL;
	}

	if (!policy || !rule || !cond) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	terule = (avtab_ptr_t) rule;

	*cond = (qpol_cond_t *) terule->parse_context;

	return STATUS_SUCCESS;
}

int qpol_terule_get_is_enabled(const qpol_policy_t * policy, const qpol_terule_t * rule, uint32_t * is_enabled)
{
	avtab_ptr_t terule = NULL;

	if (is_enabled) {
		*is_enabled = 0;
	}

	if (!policy || !rule || !is_enabled) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	terule = (avtab_ptr_t) rule;

	*is_enabled = ((terule->merged & QPOL_COND_RULE_ENABLED) ? 1 : 0);

	return STATUS_SUCCESS;
}

int qpol_terule_get_which_list(const qpol_policy_t * policy, const qpol_terule_t * rule, uint32_t * which_list)
{
	avtab_ptr_t terule = NULL;

	if (which_list) {
		*which_list = 0;
	}

	if (!policy || !rule || !which_list) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	terule = (avtab_ptr_t) rule;

	if (!terule->parse_context) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*which_list = ((terule->merged & QPOL_COND_RULE_LIST) ? 1 : 0);

	return STATUS_SUCCESS;
}
