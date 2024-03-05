/**
*  @file
*  Defines the public interface for searching and iterating over the policy capabilities.
*
*  @author Steve Lawrence slawrence@tresys.com
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
#include <qpol/polcap_query.h>
#include <sepol/policydb/policydb.h>
#include "qpol_internal.h"
#include "iterator_internal.h"

	
int qpol_polcap_get_name(const qpol_policy_t *policy, const qpol_polcap_t * datum, const char **name)
{
	char *internal_datum = NULL;
	
	if (policy == NULL || datum == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (char *) datum;
	*name = internal_datum;
		
	return STATUS_SUCCESS;
}

int qpol_policy_get_polcap_iter(const qpol_policy_t *policy, qpol_iterator_t **iter)
{
	int error = 0;
	policydb_t *db;
	ebitmap_state_t *state = NULL;

	if (iter) {
		*iter = NULL;
	}

	if (policy == NULL || iter == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	state = calloc(1, sizeof(ebitmap_state_t));
	if (state == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}

	state->bmap = &(db->policycaps);
	state->cur = state->bmap->node ? state->bmap->node->startbit : 0;

	if (qpol_iterator_create(policy, state, ebitmap_state_get_cur_polcap,
				 ebitmap_state_next, ebitmap_state_end, ebitmap_state_size, free, iter)) {
		free(state);
		return STATUS_ERR;
	}

	if (state->bmap->node && !ebitmap_get_bit(state->bmap, state->cur))
		ebitmap_state_next(*iter);

	return STATUS_SUCCESS;
}
