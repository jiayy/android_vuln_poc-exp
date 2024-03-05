/**
*  @file
*  Defines the public interface for searching and iterating over fs_use statements.
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
#include <stdlib.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/fs_use_query.h>
#include <qpol/context_query.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/context.h>
#include "qpol_internal.h"
#include "iterator_internal.h"

int qpol_policy_get_fs_use_by_name(const qpol_policy_t * policy, const char *name, const qpol_fs_use_t ** ocon)
{
	ocontext_t *tmp = NULL;
	policydb_t *db = NULL;

	if (ocon != NULL)
		*ocon = NULL;

	if (policy == NULL || name == NULL || ocon == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	for (tmp = db->ocontexts[OCON_FSUSE]; tmp; tmp = tmp->next) {
		if (!strcmp(name, tmp->u.name))
			break;
	}

	*ocon = (qpol_fs_use_t *) tmp;

	if (*ocon == NULL) {
		ERR(policy, "could not find fs_use statement for %s", name);
		errno = ENOENT;
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_policy_get_fs_use_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
{
	policydb_t *db = NULL;
	int error = 0;
	ocon_state_t *os = NULL;

	if (iter != NULL)
		*iter = NULL;

	if (policy == NULL || iter == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	os = calloc(1, sizeof(ocon_state_t));
	if (os == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}

	os->head = os->cur = db->ocontexts[OCON_FSUSE];

	if (qpol_iterator_create(policy, (void *)os, ocon_state_get_cur,
				 ocon_state_next, ocon_state_end, ocon_state_size, free, iter)) {
		free(os);
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_fs_use_get_name(const qpol_policy_t * policy, const qpol_fs_use_t * ocon, const char **name)
{
	ocontext_t *internal_ocon = NULL;

	if (name != NULL)
		*name = NULL;

	if (policy == NULL || ocon == NULL || name == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;
	*name = internal_ocon->u.name;

	return STATUS_SUCCESS;
}

int qpol_fs_use_get_behavior(const qpol_policy_t * policy, const qpol_fs_use_t * ocon, uint32_t * behavior)
{
	ocontext_t *internal_ocon = NULL;

	if (behavior != NULL)
		*behavior = 0;

	if (policy == NULL || ocon == NULL || behavior == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;
	*behavior = internal_ocon->v.behavior;

	return STATUS_SUCCESS;
}

int qpol_fs_use_get_context(const qpol_policy_t * policy, const qpol_fs_use_t * ocon, const qpol_context_t ** context)
{
	ocontext_t *internal_ocon = NULL;

	if (context != NULL)
		*context = NULL;

	if (policy == NULL || ocon == NULL || context == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;

	if (internal_ocon->v.behavior == QPOL_FS_USE_PSID) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*context = (qpol_context_t *) & (internal_ocon->context[0]);

	return STATUS_SUCCESS;
}
