/**
 * @file
 *
 * Provides a way for setools to make queries about roles within a
 * policy.  The caller obtains a query object, fills in its
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

struct apol_role_query
{
	char *role_name, *type_name;
	unsigned int flags;
	regex_t *role_regex, *type_regex;
};

/******************** role queries ********************/

int apol_role_get_by_query(const apol_policy_t * p, apol_role_query_t * r, apol_vector_t ** v)
{
	qpol_iterator_t *iter = NULL, *type_iter = NULL;
	int retval = -1, append_role;
	*v = NULL;
	if (qpol_policy_get_role_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_role_t *role;
		if (qpol_iterator_get_item(iter, (void **)&role) < 0) {
			goto cleanup;
		}
		append_role = 1;
		if (r != NULL) {
			const char *role_name;
			int compval;
			if (qpol_role_get_name(p->p, role, &role_name) < 0) {
				goto cleanup;
			}
			compval = apol_compare(p, role_name, r->role_name, r->flags, &(r->role_regex));
			if (compval < 0) {
				goto cleanup;
			} else if (compval == 0) {
				continue;
			}
			if (r->type_name == NULL || r->type_name[0] == '\0') {
				goto end_of_query;
			}
			if (qpol_role_get_type_iter(p->p, role, &type_iter) < 0) {
				goto cleanup;
			}
			append_role = 0;
			for (; !qpol_iterator_end(type_iter); qpol_iterator_next(type_iter)) {
				qpol_type_t *type;
				if (qpol_iterator_get_item(type_iter, (void **)&type) < 0) {
					goto cleanup;
				}
				compval = apol_compare_type(p, type, r->type_name, r->flags, &(r->type_regex));
				if (compval < 0) {
					goto cleanup;
				} else if (compval == 1) {
					append_role = 1;
					break;
				}
			}
			qpol_iterator_destroy(&type_iter);
		}
	      end_of_query:
		if (append_role && apol_vector_append(*v, role)) {
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
	qpol_iterator_destroy(&type_iter);
	return retval;
}

apol_role_query_t *apol_role_query_create(void)
{
	return calloc(1, sizeof(apol_role_query_t));
}

void apol_role_query_destroy(apol_role_query_t ** r)
{
	if (*r != NULL) {
		free((*r)->role_name);
		free((*r)->type_name);
		apol_regex_destroy(&(*r)->role_regex);
		apol_regex_destroy(&(*r)->type_regex);
		free(*r);
		*r = NULL;
	}
}

int apol_role_query_set_role(const apol_policy_t * p, apol_role_query_t * r, const char *name)
{
	return apol_query_set(p, &r->role_name, &r->role_regex, name);
}

int apol_role_query_set_type(const apol_policy_t * p, apol_role_query_t * r, const char *name)
{
	return apol_query_set(p, &r->type_name, &r->type_regex, name);
}

int apol_role_query_set_regex(const apol_policy_t * p, apol_role_query_t * r, int is_regex)
{
	return apol_query_set_regex(p, &r->flags, is_regex);
}

int apol_role_has_type(const apol_policy_t * p, const qpol_role_t * r, const qpol_type_t * t)
{
	qpol_iterator_t *iter = NULL;
	qpol_type_t *tmp_type;
	uint32_t type_value, t_type_value;
	int retval = -1;

	if (qpol_type_get_value(p->p, t, &t_type_value) < 0 || qpol_role_get_type_iter(p->p, r, &iter) < 0) {
		goto cleanup;
	}

	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_iterator_get_item(iter, (void **)(&tmp_type));
		qpol_type_get_value(p->p, tmp_type, &type_value);
		if (t_type_value == type_value) {
			retval = 1;
			goto cleanup;
		}
	}
	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
	return retval;
}
