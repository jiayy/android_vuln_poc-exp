/**
 * @file
 *
 * Provides a way for setools to make queries about conditional
 * expressions rules within a policy.  The caller obtains a query
 * object, fills in its parameters, and then runs the query; it
 * obtains a vector of results.  Searches are conjunctive -- all
 * fields of the search query must match for a datum to be added to
 * the results query.
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

struct apol_cond_query
{
	char *bool_name;
	unsigned int flags;
	regex_t *regex;
};

int apol_cond_get_by_query(const apol_policy_t * p, apol_cond_query_t * c, apol_vector_t ** v)
{
	qpol_iterator_t *iter = NULL;
	int retval = -1;
	*v = NULL;

	if (qpol_policy_get_cond_iter(p->p, &iter) < 0) {
		goto cleanup;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_cond_t *cond;
		if (qpol_iterator_get_item(iter, (void **)&cond) < 0) {
			goto cleanup;
		}
		if (c != NULL) {
			int keep_cond = apol_compare_cond_expr(p, cond, c->bool_name, c->flags, &c->regex);
			if (keep_cond < 0) {
				goto cleanup;
			} else if (keep_cond == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, cond)) {
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

apol_cond_query_t *apol_cond_query_create(void)
{
	return calloc(1, sizeof(apol_cond_query_t));
}

void apol_cond_query_destroy(apol_cond_query_t ** c)
{
	if (*c != NULL) {
		free((*c)->bool_name);
		apol_regex_destroy(&(*c)->regex);
		free(*c);
		*c = NULL;
	}
}

int apol_cond_query_set_bool(const apol_policy_t * p, apol_cond_query_t * c, const char *name)
{
	return apol_query_set(p, &c->bool_name, &c->regex, name);
}

int apol_cond_query_set_regex(const apol_policy_t * p, apol_cond_query_t * c, int is_regex)
{
	return apol_query_set_regex(p, &c->flags, is_regex);
}

char *apol_cond_expr_render(const apol_policy_t * p, const qpol_cond_t * cond)
{
	qpol_iterator_t *iter = NULL;
	qpol_cond_expr_node_t *expr = NULL;
	char *tmp = NULL;
	const char *bool_name = NULL;
	int error = 0;
	size_t tmp_sz = 0, i;
	uint32_t expr_type = 0;
	qpol_bool_t *cond_bool = NULL;

	if (!p || !cond) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	if (qpol_cond_get_expr_node_iter(p->p, cond, &iter) < 0) {
		error = errno;
		goto err;
	}

	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&expr)) {
			error = errno;
			ERR(p, "%s", strerror(error));
			goto err;
		}
		if (qpol_cond_expr_node_get_expr_type(p->p, expr, &expr_type)) {
			error = errno;
			ERR(p, "%s", strerror(error));
			goto err;
		}
		if (expr_type != QPOL_COND_EXPR_BOOL) {
			if (apol_str_append(&tmp, &tmp_sz, apol_cond_expr_type_to_str(expr_type))) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto err;
			}
		} else {
			if (qpol_cond_expr_node_get_bool(p->p, expr, &cond_bool)) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto err;
			}
			if (qpol_bool_get_name(p->p, cond_bool, &bool_name)) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto err;
			}
			if (apol_str_append(&tmp, &tmp_sz, bool_name)) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto err;
			}
		}
		if (apol_str_append(&tmp, &tmp_sz, " ")) {
			error = errno;
			ERR(p, "%s", strerror(error));
			goto err;
		}
	}

	/* remove trailing space */
	i = strlen(tmp);
	if (i > 1) {
		tmp[i - 1] = '\0';
	}
	qpol_iterator_destroy(&iter);
	return tmp;

      err:
	qpol_iterator_destroy(&iter);
	free(tmp);
	errno = error;
	return NULL;
}
