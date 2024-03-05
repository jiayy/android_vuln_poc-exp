/**
 * @file
 *
 * Provides a way for setools to make queries about initial SIDs
 * within a policy.  The caller obtains a query object, fills in its
 * parameters, and then runs the query; it obtains a vector of
 * results.  Searches are conjunctive -- all fields of the search
 * query must match for a datum to be added to the results query.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
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

#include "policy-query-internal.h"

#include <errno.h>

struct apol_isid_query
{
	char *name;
	apol_context_t *context;
	unsigned int flags;
};

/******************** genfscon queries ********************/

int apol_isid_get_by_query(const apol_policy_t * p, const apol_isid_query_t * i, apol_vector_t ** v)
{
	qpol_iterator_t *iter;
	int retval = -1, retval2;
	const qpol_isid_t *isid = NULL;
	*v = NULL;
	if (qpol_policy_get_isid_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&isid) < 0) {
			goto cleanup;
		}
		if (i != NULL) {
			const char *name;
			const qpol_context_t *context;
			if (qpol_isid_get_name(p->p, isid, &name) < 0 || qpol_isid_get_context(p->p, isid, &context) < 0) {
				goto cleanup;
			}
			retval2 = apol_compare(p, name, i->name, 0, NULL);
			if (retval2 < 0) {
				goto cleanup;
			} else if (retval2 == 0) {
				continue;
			}
			retval2 = apol_compare_context(p, context, i->context, i->flags);
			if (retval2 < 0) {
				goto cleanup;
			} else if (retval2 == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, (void *)isid)) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	if (retval != 0) {
		apol_vector_destroy(v);
	}
	qpol_iterator_destroy(&iter);
	return retval;
}

apol_isid_query_t *apol_isid_query_create(void)
{
	return calloc(1, sizeof(apol_isid_query_t));
}

void apol_isid_query_destroy(apol_isid_query_t ** i)
{
	if (*i != NULL) {
		free((*i)->name);
		apol_context_destroy(&((*i)->context));
		free(*i);
		*i = NULL;
	}
}

int apol_isid_query_set_name(const apol_policy_t * p, apol_isid_query_t * i, const char *name)
{
	return apol_query_set(p, &i->name, NULL, name);
}

int apol_isid_query_set_context(const apol_policy_t * p __attribute__ ((unused)),
				apol_isid_query_t * i, apol_context_t * context, unsigned int range_match)
{
	if (i->context != NULL) {
		apol_context_destroy(&i->context);
	}
	i->context = context;
	i->flags = (i->flags & ~APOL_QUERY_FLAGS) | range_match;
	return 0;
}
