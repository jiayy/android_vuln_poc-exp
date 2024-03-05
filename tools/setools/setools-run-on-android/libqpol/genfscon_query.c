/**
*  @file
*  Defines the public interface for searching and iterating over genfscon statements.
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
#include <qpol/context_query.h>
#include <qpol/genfscon_query.h>
#include <sepol/policydb/policydb.h>
#include "qpol_internal.h"
#include "iterator_internal.h"

struct qpol_genfscon
{
	const char *fs_name;
	const char *path;
	const context_struct_t *context;
	uint32_t sclass;
};

int qpol_policy_get_genfscon_by_name(const qpol_policy_t * policy, const char *name, const char *path, qpol_genfscon_t ** genfscon)
{
	genfs_t *tmp = NULL;
	ocontext_t *tmp2 = NULL;
	policydb_t *db = NULL;

	if (genfscon != NULL)
		*genfscon = NULL;

	if (policy == NULL || name == NULL || path == NULL || genfscon == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	for (tmp = db->genfs; tmp; tmp = tmp->next) {
		if (!strcmp(name, tmp->fstype))
			break;
	}

	if (tmp) {
		for (tmp2 = tmp->head; tmp2; tmp2 = tmp2->next) {
			if (!strcmp(path, tmp2->u.name))
				break;
		}
	}

	if (tmp && tmp2) {
		*genfscon = calloc(1, sizeof(qpol_genfscon_t));
		if (!(*genfscon)) {
			ERR(policy, "%s", strerror(ENOMEM));
			errno = errno;
			return STATUS_ERR;
		}
		/* shallow copy only the struct pointer (genfscon) should be free()'ed */
		(*genfscon)->fs_name = tmp->fstype;
		(*genfscon)->path = tmp2->u.name;
		(*genfscon)->context = &(tmp2->context[0]);
		(*genfscon)->sclass = tmp2->v.sclass;
	}

	if (*genfscon == NULL) {
		ERR(policy, "could not find genfscon statement for %s %s", name, path);
		errno = ENOENT;
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

typedef struct genfs_state
{
	genfs_t *head;
	genfs_t *cur;
	ocontext_t *cur_path;
} genfs_state_t;

static int genfs_state_end(const qpol_iterator_t * iter)
{
	genfs_state_t *gs = NULL;

	if (iter == NULL || qpol_iterator_state(iter) == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	gs = (genfs_state_t *) qpol_iterator_state(iter);

	if (gs->cur == NULL && gs->cur_path == NULL)
		return 1;

	return 0;
}

static void *genfs_state_get_cur(const qpol_iterator_t * iter)
{
	genfs_state_t *gs = NULL;
	qpol_genfscon_t *genfscon = NULL;

	if (iter == NULL || qpol_iterator_state(iter) == NULL || genfs_state_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	gs = (genfs_state_t *) qpol_iterator_state(iter);

	genfscon = calloc(1, sizeof(qpol_genfscon_t));
	if (!genfscon) {
		return NULL;
	}

	genfscon->fs_name = gs->cur->fstype;
	genfscon->path = gs->cur_path->u.name;
	genfscon->context = &(gs->cur_path->context[0]);
	genfscon->sclass = gs->cur_path->v.sclass;

	return genfscon;
}

static size_t genfs_state_size(const qpol_iterator_t * iter)
{
	genfs_state_t *gs = NULL;
	size_t count = 0;
	genfs_t *genfs = NULL;
	ocontext_t *path = NULL;

	if (iter == NULL || qpol_iterator_state(iter) == NULL) {
		errno = EINVAL;
		return 0;
	}

	gs = (genfs_state_t *) qpol_iterator_state(iter);

	for (genfs = gs->head; genfs; genfs = genfs->next)
		for (path = genfs->head; path; path = path->next)
			count++;

	return count;
}

static int genfs_state_next(qpol_iterator_t * iter)
{
	genfs_state_t *gs = NULL;

	if (iter == NULL || qpol_iterator_state(iter) == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	gs = (genfs_state_t *) qpol_iterator_state(iter);

	if (gs->cur == NULL) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	if (gs->cur_path->next != NULL) {
		gs->cur_path = gs->cur_path->next;
	} else {
		gs->cur = gs->cur->next;
		gs->cur_path = gs->cur ? gs->cur->head : NULL;
	}

	return STATUS_SUCCESS;
}

int qpol_policy_get_genfscon_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
{
	policydb_t *db = NULL;
	genfs_state_t *gs = NULL;
	int error = 0;

	if (iter != NULL)
		*iter = NULL;

	if (policy == NULL || iter == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	gs = calloc(1, sizeof(genfs_state_t));
	if (gs == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}

	gs->head = gs->cur = db->genfs;
	if (gs->head)
		gs->cur_path = gs->head->head;

	if (qpol_iterator_create(policy, (void *)gs, genfs_state_get_cur,
				 genfs_state_next, genfs_state_end, genfs_state_size, free, iter)) {
		free(gs);
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_genfscon_get_name(const qpol_policy_t * policy, const qpol_genfscon_t * genfs, const char **name)
{
	if (name != NULL)
		*name = NULL;

	if (policy == NULL || genfs == NULL || name == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*name = genfs->fs_name;

	return STATUS_SUCCESS;
}

int qpol_genfscon_get_path(const qpol_policy_t * policy, const qpol_genfscon_t * genfs, const char **path)
{
	if (path != NULL)
		*path = NULL;

	if (policy == NULL || genfs == NULL || path == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*path = genfs->path;

	return STATUS_SUCCESS;
}

int qpol_genfscon_get_class(const qpol_policy_t * policy, const qpol_genfscon_t * genfs, uint32_t * obj_class)
{
	if (obj_class != NULL)
		*obj_class = 0;

	if (policy == NULL || genfs == NULL || obj_class == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*obj_class = genfs->sclass;

	return STATUS_SUCCESS;
}

int qpol_genfscon_get_context(const qpol_policy_t * policy, const qpol_genfscon_t * genfscon, const qpol_context_t ** context)
{
	if (context != NULL)
		*context = NULL;

	if (policy == NULL || genfscon == NULL || context == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*context = (qpol_context_t *) genfscon->context;

	return STATUS_SUCCESS;
}
