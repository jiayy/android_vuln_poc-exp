/**
 *  @file
 *  Defines the public interface for searching and iterating over portcon statements.
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
#include <netinet/in.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/context_query.h>
#include <qpol/portcon_query.h>
#include <sepol/policydb/policydb.h>
#include "qpol_internal.h"
#include "iterator_internal.h"

int qpol_policy_get_portcon_by_port(const qpol_policy_t * policy, uint16_t low, uint16_t high, uint8_t protocol,
				    const qpol_portcon_t ** ocon)
{
	ocontext_t *tmp = NULL;
	policydb_t *db = NULL;

	if (ocon != NULL)
		*ocon = NULL;

	if (policy == NULL || ocon == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	for (tmp = db->ocontexts[OCON_PORT]; tmp; tmp = tmp->next) {
		if (tmp->u.port.low_port == low && tmp->u.port.high_port == high && tmp->u.port.protocol == protocol)
			break;
	}

	*ocon = (qpol_portcon_t *) tmp;

	if (*ocon == NULL) {
		ERR(policy, "could not find portcon statement for %u-%u:%u", low, high, protocol);
		errno = ENOENT;
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_policy_get_portcon_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
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

	os->head = os->cur = db->ocontexts[OCON_PORT];

	if (qpol_iterator_create(policy, (void *)os, ocon_state_get_cur,
				 ocon_state_next, ocon_state_end, ocon_state_size, free, iter)) {
		free(os);
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_portcon_get_protocol(const qpol_policy_t * policy, const qpol_portcon_t * ocon, uint8_t * protocol)
{
	ocontext_t *internal_ocon = NULL;

	if (protocol != NULL)
		*protocol = 0;

	if (policy == NULL || ocon == NULL || protocol == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;

	*protocol = internal_ocon->u.port.protocol;

	return STATUS_SUCCESS;
}

int qpol_portcon_get_low_port(const qpol_policy_t * policy, const qpol_portcon_t * ocon, uint16_t * port)
{
	ocontext_t *internal_ocon = NULL;

	if (port != NULL)
		*port = 0;

	if (policy == NULL || ocon == NULL || port == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;

	*port = internal_ocon->u.port.low_port;

	return STATUS_SUCCESS;
}

int qpol_portcon_get_high_port(const qpol_policy_t * policy, const qpol_portcon_t * ocon, uint16_t * port)
{
	ocontext_t *internal_ocon = NULL;

	if (port != NULL)
		*port = 0;

	if (policy == NULL || ocon == NULL || port == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;

	*port = internal_ocon->u.port.high_port;

	return STATUS_SUCCESS;
}

int qpol_portcon_get_context(const qpol_policy_t * policy, const qpol_portcon_t * ocon, const qpol_context_t ** context)
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
	*context = (qpol_context_t *) & (internal_ocon->context[0]);

	return STATUS_SUCCESS;
}
