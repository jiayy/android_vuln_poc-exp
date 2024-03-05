/**
*  @file
*  Defines the public interface for searching and iterating over nodecon statements.
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
#include <qpol/nodecon_query.h>
#include <sepol/policydb/policydb.h>
#include "qpol_internal.h"
#include "iterator_internal.h"

struct qpol_nodecon
{
	ocontext_t *ocon;
	unsigned char protocol;
};

int qpol_policy_get_nodecon_by_node(const qpol_policy_t * policy, uint32_t addr[4], uint32_t mask[4], unsigned char protocol,
				    qpol_nodecon_t ** ocon)
{
	policydb_t *db = NULL;
	ocontext_t *tmp = NULL;
	int error = 0;

	if (ocon != NULL)
		*ocon = NULL;

	if (policy == NULL || ocon == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	for (tmp = db->ocontexts[(protocol == QPOL_IPV4 ? OCON_NODE : OCON_NODE6)]; tmp; tmp = tmp->next) {
		if (protocol == QPOL_IPV4) {
			if (addr[0] != tmp->u.node.addr || mask[0] != tmp->u.node.mask)
				continue;
		} else {
			if (memcmp(addr, tmp->u.node6.addr, 16) || memcmp(mask, tmp->u.node6.mask, 16))
				continue;
		}
		*ocon = calloc(1, sizeof(qpol_nodecon_t));
		if (*ocon == NULL) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			errno = error;
			return STATUS_ERR;
		}

		(*ocon)->protocol = protocol == QPOL_IPV4 ? QPOL_IPV4 : QPOL_IPV6;
		(*ocon)->ocon = tmp;
	}

	if (*ocon == NULL) {
		ERR(policy, "%s", "could not find nodecon statement for node");
		errno = ENOENT;
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

typedef struct node_state
{
	ocon_state_t *v4state;
	ocon_state_t *v6state;
} node_state_t;

static void node_state_free(void *ns)
{
	node_state_t *ins = (node_state_t *) ns;

	if (!ns)
		return;

	free(ins->v4state);
	free(ins->v6state);
	free(ns);
}

static int node_state_end(const qpol_iterator_t * iter)
{
	node_state_t *ns = NULL;

	if (iter == NULL || qpol_iterator_state(iter) == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	ns = (node_state_t *) qpol_iterator_state(iter);

	return (ns->v4state->cur == NULL && ns->v6state->cur == NULL);
}

static void *node_state_get_cur(const qpol_iterator_t * iter)
{
	node_state_t *ns = NULL;
	qpol_nodecon_t *node = NULL;

	if (iter == NULL || qpol_iterator_state(iter) == NULL || node_state_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	ns = (node_state_t *) qpol_iterator_state(iter);

	node = calloc(1, sizeof(qpol_nodecon_t));
	if (!node) {
		return NULL;
	}

	node->ocon = ns->v4state->cur ? ns->v4state->cur : ns->v6state->cur;
	node->protocol = ns->v4state->cur ? QPOL_IPV4 : QPOL_IPV6;

	return node;
}

static size_t node_state_size(const qpol_iterator_t * iter)
{
	node_state_t *ns = NULL;
	size_t count = 0;
	ocontext_t *ocon = NULL;

	if (iter == NULL || qpol_iterator_state(iter) == NULL) {
		errno = EINVAL;
		return 0;
	}

	ns = (node_state_t *) qpol_iterator_state(iter);

	if (ns->v4state)
		for (ocon = ns->v4state->head; ocon; ocon = ocon->next)
			count++;

	if (ns->v6state)
		for (ocon = ns->v6state->head; ocon; ocon = ocon->next)
			count++;

	return count;
}

static int node_state_next(qpol_iterator_t * iter)
{
	node_state_t *ns = NULL;

	if (iter == NULL || qpol_iterator_state(iter) == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	ns = (node_state_t *) qpol_iterator_state(iter);

	if (ns->v4state->cur == NULL && ns->v6state->cur == NULL) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	if (ns->v4state->cur)
		ns->v4state->cur = ns->v4state->cur->next;
	else
		ns->v6state->cur = ns->v6state->cur->next;

	return STATUS_SUCCESS;
}

int qpol_policy_get_nodecon_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
{
	policydb_t *db = NULL;
	int error = 0;
	ocon_state_t *v4os = NULL, *v6os = NULL;
	node_state_t *ns = NULL;

	if (iter != NULL)
		*iter = NULL;

	if (policy == NULL || iter == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	v4os = calloc(1, sizeof(ocon_state_t));
	if (v4os == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}
	v4os->head = v4os->cur = db->ocontexts[OCON_NODE];

	v6os = calloc(1, sizeof(ocon_state_t));
	if (v6os == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		free(v4os);
		errno = error;
		return STATUS_ERR;
	}
	v6os->head = v6os->cur = db->ocontexts[OCON_NODE6];

	ns = calloc(1, sizeof(node_state_t));
	if (ns == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		free(v4os);
		free(v6os);
		errno = error;
		return STATUS_ERR;
	}
	ns->v4state = v4os;
	ns->v6state = v6os;

	if (qpol_iterator_create(policy, (void *)ns, node_state_get_cur,
				 node_state_next, node_state_end, node_state_size, node_state_free, iter)) {
		node_state_free(ns);
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_nodecon_get_addr(const qpol_policy_t * policy, const qpol_nodecon_t * ocon, uint32_t ** addr, unsigned char *protocol)
{
	if (addr != NULL)
		*addr = NULL;
	if (protocol != NULL)
		*protocol = 0;

	if (policy == NULL || ocon == NULL || addr == NULL || protocol == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*protocol = ocon->protocol;

	if (ocon->protocol == QPOL_IPV4) {
		*addr = &(ocon->ocon->u.node.addr);
	} else {
		*addr = ocon->ocon->u.node6.addr;
	}

	return STATUS_SUCCESS;
}

int qpol_nodecon_get_mask(const qpol_policy_t * policy, const qpol_nodecon_t * ocon, uint32_t ** mask, unsigned char *protocol)
{
	if (mask != NULL)
		*mask = NULL;
	if (protocol != NULL)
		*protocol = 0;

	if (policy == NULL || ocon == NULL || mask == NULL || protocol == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*protocol = ocon->protocol;

	if (ocon->protocol == QPOL_IPV4) {
		*mask = &(ocon->ocon->u.node.mask);
	} else {
		*mask = ocon->ocon->u.node6.mask;
	}

	return STATUS_SUCCESS;
}

int qpol_nodecon_get_protocol(const qpol_policy_t * policy, const qpol_nodecon_t * ocon, unsigned char *protocol)
{
	if (protocol != NULL)
		*protocol = 0;

	if (policy == NULL || ocon == NULL || protocol == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*protocol = ocon->protocol;

	return STATUS_SUCCESS;
}

int qpol_nodecon_get_context(const qpol_policy_t * policy, const qpol_nodecon_t * ocon, const qpol_context_t ** context)
{
	if (context != NULL)
		*context = NULL;

	if (policy == NULL || ocon == NULL || context == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*context = (qpol_context_t *) & (ocon->ocon->context[0]);

	return STATUS_SUCCESS;
}
