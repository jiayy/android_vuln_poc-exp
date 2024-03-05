/**
 * @file
 *
 * Provides a way for setools to make queries about classes, commons,
 * and permissions within a policy.  The caller obtains a query
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
#include <string.h>

struct apol_class_query
{
	char *class_name, *common_name;
	unsigned int flags;
	regex_t *class_regex, *common_regex;
};

struct apol_common_query
{
	char *common_name;
	unsigned int flags;
	regex_t *regex;
};

struct apol_perm_query
{
	char *perm_name;
	unsigned int flags;
	regex_t *regex;
};

/******************** class queries ********************/

int apol_class_get_by_query(const apol_policy_t * p, apol_class_query_t * c, apol_vector_t ** v)
{
	qpol_iterator_t *iter = NULL, *perm_iter = NULL;
	int retval = -1, append_class;
	*v = NULL;
	if (qpol_policy_get_class_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_class_t *class_datum;
		if (qpol_iterator_get_item(iter, (void **)&class_datum) < 0) {
			goto cleanup;
		}
		append_class = 1;
		if (c != NULL) {
			const char *class_name, *common_name = NULL;
			const qpol_common_t *common_datum;
			int compval;
			if (qpol_class_get_name(p->p, class_datum, &class_name) < 0) {
				goto cleanup;
			}
			compval = apol_compare(p, class_name, c->class_name, c->flags, &(c->class_regex));
			if (compval < 0) {
				goto cleanup;
			} else if (compval == 0) {
				continue;
			}
			if (qpol_class_get_common(p->p, class_datum, &common_datum) < 0) {
				goto cleanup;
			}
			if (common_datum == NULL) {
				if (c->common_name != NULL && c->common_name[0] != '\0') {
					continue;
				}
			} else {
				if (qpol_common_get_name(p->p, common_datum, &common_name) < 0) {
					goto cleanup;
				}
				compval = apol_compare(p, common_name, c->common_name, c->flags, &(c->common_regex));
				if (compval < 0) {
					goto cleanup;
				} else if (compval == 0) {
					continue;
				}
			}
		}
		if (append_class && apol_vector_append(*v, class_datum)) {
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
	qpol_iterator_destroy(&perm_iter);
	return retval;
}

apol_class_query_t *apol_class_query_create(void)
{
	return calloc(1, sizeof(apol_class_query_t));
}

void apol_class_query_destroy(apol_class_query_t ** c)
{
	if (*c != NULL) {
		free((*c)->class_name);
		free((*c)->common_name);
		apol_regex_destroy(&(*c)->class_regex);
		apol_regex_destroy(&(*c)->common_regex);
		free(*c);
		*c = NULL;
	}
}

int apol_class_query_set_class(const apol_policy_t * p, apol_class_query_t * c, const char *name)
{
	return apol_query_set(p, &c->class_name, &c->class_regex, name);
}

int apol_class_query_set_common(const apol_policy_t * p, apol_class_query_t * c, const char *name)
{
	return apol_query_set(p, &c->common_name, &c->common_regex, name);
}

int apol_class_query_set_regex(const apol_policy_t * p, apol_class_query_t * c, int is_regex)
{
	return apol_query_set_regex(p, &c->flags, is_regex);
}

/******************** common queries ********************/

int apol_common_get_by_query(const apol_policy_t * p, apol_common_query_t * c, apol_vector_t ** v)
{
	qpol_iterator_t *iter = NULL;
	int retval = -1;
	*v = NULL;
	if (qpol_policy_get_common_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_common_t *common_datum;
		if (qpol_iterator_get_item(iter, (void **)&common_datum) < 0) {
			goto cleanup;
		}
		if (c != NULL) {
			const char *common_name = NULL;
			int compval;
			if (qpol_common_get_name(p->p, common_datum, &common_name) < 0) {
				goto cleanup;
			}
			compval = apol_compare(p, common_name, c->common_name, c->flags, &(c->regex));
			if (compval < 0) {
				goto cleanup;
			} else if (compval == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, common_datum)) {
			ERR(p, "%s", strerror(errno));
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

apol_common_query_t *apol_common_query_create(void)
{
	return calloc(1, sizeof(apol_common_query_t));
}

void apol_common_query_destroy(apol_common_query_t ** c)
{
	if (*c != NULL) {
		free((*c)->common_name);
		apol_regex_destroy(&(*c)->regex);
		free(*c);
		*c = NULL;
	}
}

int apol_common_query_set_common(const apol_policy_t * p, apol_common_query_t * c, const char *name)
{
	return apol_query_set(p, &c->common_name, &c->regex, name);
}

int apol_common_query_set_regex(const apol_policy_t * p, apol_common_query_t * c, int is_regex)
{
	return apol_query_set_regex(p, &c->flags, is_regex);
}

/******************** permission queries ********************/

int apol_perm_get_by_query(const apol_policy_t * p, apol_perm_query_t * pq, apol_vector_t ** v)
{
	qpol_iterator_t *class_iter = NULL, *common_iter = NULL, *perm_iter = NULL;
	int retval = -1, compval;
	char *perm_name;
	*v = NULL;
	if (qpol_policy_get_class_iter(p->p, &class_iter) < 0 || qpol_policy_get_common_iter(p->p, &common_iter) < 0) {
		goto cleanup;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(class_iter); qpol_iterator_next(class_iter)) {
		qpol_class_t *class_datum;
		if (qpol_iterator_get_item(class_iter, (void **)&class_datum) < 0 ||
		    qpol_class_get_perm_iter(p->p, class_datum, &perm_iter) < 0) {
			goto cleanup;
		}
		for (; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
			if (qpol_iterator_get_item(perm_iter, (void **)&perm_name) < 0) {
				goto cleanup;
			}
			if (pq == NULL) {
				compval = 1;
			} else {
				compval = apol_compare(p, perm_name, pq->perm_name, pq->flags, &(pq->regex));
			}
			if (compval < 0) {
				goto cleanup;
			} else if (compval == 1 && apol_vector_append_unique(*v, perm_name, apol_str_strcmp, NULL) < 0) {
				ERR(p, "%s", strerror(ENOMEM));
				goto cleanup;
			}
		}
		qpol_iterator_destroy(&perm_iter);
	}

	for (; !qpol_iterator_end(common_iter); qpol_iterator_next(common_iter)) {
		qpol_common_t *common_datum;
		if (qpol_iterator_get_item(common_iter, (void **)&common_datum) < 0 ||
		    qpol_common_get_perm_iter(p->p, common_datum, &perm_iter) < 0) {
			goto cleanup;
		}
		for (; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
			if (qpol_iterator_get_item(perm_iter, (void **)&perm_name) < 0) {
				goto cleanup;
			}
			if (pq == NULL) {
				compval = 1;
			} else {
				compval = apol_compare(p, perm_name, pq->perm_name, pq->flags, &(pq->regex));
			}
			if (compval < 0) {
				goto cleanup;
			} else if (compval == 1 && apol_vector_append_unique(*v, perm_name, apol_str_strcmp, NULL) < 0) {
				ERR(p, "%s", strerror(ENOMEM));
				goto cleanup;
			}
		}
		qpol_iterator_destroy(&perm_iter);
	}

	retval = 0;
      cleanup:
	if (retval != 0) {
		apol_vector_destroy(v);
	}
	qpol_iterator_destroy(&class_iter);
	qpol_iterator_destroy(&common_iter);
	qpol_iterator_destroy(&perm_iter);
	return retval;
}

apol_perm_query_t *apol_perm_query_create(void)
{
	return calloc(1, sizeof(apol_perm_query_t));
}

void apol_perm_query_destroy(apol_perm_query_t ** pq)
{
	if (*pq != NULL) {
		free((*pq)->perm_name);
		apol_regex_destroy(&(*pq)->regex);
		free(*pq);
		*pq = NULL;
	}
}

int apol_perm_query_set_perm(const apol_policy_t * p, apol_perm_query_t * pq, const char *name)
{
	return apol_query_set(p, &pq->perm_name, &pq->regex, name);
}

int apol_perm_query_set_regex(const apol_policy_t * p, apol_perm_query_t * pq, int is_regex)
{
	return apol_query_set_regex(p, &pq->flags, is_regex);
}
