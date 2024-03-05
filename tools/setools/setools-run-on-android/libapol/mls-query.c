/**
 *  @file
 *  Implementation for querying MLS components.
 *
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

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>

#include <qpol/iterator.h>

#include "policy-query-internal.h"
#include <apol/vector.h>

struct apol_level_query
{
	char *sens_name, *cat_name;
	unsigned int flags;
	regex_t *sens_regex, *cat_regex;
};

struct apol_cat_query
{
	char *cat_name;
	unsigned int flags;
	regex_t *regex;
};

int apol_mls_sens_compare(const apol_policy_t * p, const char *sens1, const char *sens2)
{
	const qpol_level_t *level_datum1, *level_datum2;
	if (qpol_policy_get_level_by_name(p->p, sens1, &level_datum1) < 0 ||
	    qpol_policy_get_level_by_name(p->p, sens2, &level_datum2) < 0) {
		return -1;
	}
	if (level_datum1 == level_datum2) {
		return 1;
	}
	return 0;
}

int apol_mls_cats_compare(const apol_policy_t * p, const char *cat1, const char *cat2)
{
	const qpol_cat_t *qcat1, *qcat2;
	if (qpol_policy_get_cat_by_name(p->p, cat1, &qcat1) < 0 || qpol_policy_get_cat_by_name(p->p, cat2, &qcat2) < 0) {
		return -1;
	}
	if (qcat1 == qcat2) {
		return 1;
	}
	return 0;
}

/******************** level queries ********************/

int apol_level_get_by_query(const apol_policy_t * p, apol_level_query_t * l, apol_vector_t ** v)
{
	qpol_iterator_t *iter, *cat_iter = NULL;
	int retval = -1, append_level;
	*v = NULL;
	if (qpol_policy_get_level_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_level_t *level;
		unsigned char isalias;
		if (qpol_iterator_get_item(iter, (void **)&level) < 0 || qpol_level_get_isalias(p->p, level, &isalias) < 0) {
			goto cleanup;
		}
		if (isalias) {
			continue;
		}
		append_level = 1;
		if (l != NULL) {
			int compval = apol_compare_level(p,
							 level, l->sens_name,
							 l->flags, &(l->sens_regex));
			if (compval < 0) {
				goto cleanup;
			} else if (compval == 0) {
				continue;
			}
			if (qpol_level_get_cat_iter(p->p, level, &cat_iter) < 0) {
				goto cleanup;
			}
			append_level = 0;
			for (; !qpol_iterator_end(cat_iter); qpol_iterator_next(cat_iter)) {
				qpol_cat_t *cat;
				if (qpol_iterator_get_item(cat_iter, (void **)&cat) < 0) {
					goto cleanup;
				}
				compval = apol_compare_cat(p, cat, l->cat_name, l->flags, &(l->cat_regex));
				if (compval < 0) {
					goto cleanup;
				} else if (compval == 1) {
					append_level = 1;
					break;
				}
			}
			qpol_iterator_destroy(&cat_iter);
		}
		if (append_level && apol_vector_append(*v, level)) {
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
	qpol_iterator_destroy(&cat_iter);
	return retval;
}

apol_level_query_t *apol_level_query_create(void)
{
	return calloc(1, sizeof(apol_level_query_t));
}

void apol_level_query_destroy(apol_level_query_t ** l)
{
	if (*l != NULL) {
		free((*l)->sens_name);
		free((*l)->cat_name);
		apol_regex_destroy(&(*l)->sens_regex);
		apol_regex_destroy(&(*l)->cat_regex);
		free(*l);
		*l = NULL;
	}
}

int apol_level_query_set_sens(const apol_policy_t * p, apol_level_query_t * l, const char *name)
{
	return apol_query_set(p, &l->sens_name, &l->sens_regex, name);
}

int apol_level_query_set_cat(const apol_policy_t * p, apol_level_query_t * l, const char *name)
{
	return apol_query_set(p, &l->cat_name, &l->cat_regex, name);
}

int apol_level_query_set_regex(const apol_policy_t * p, apol_level_query_t * l, int is_regex)
{
	return apol_query_set_regex(p, &l->flags, is_regex);
}

/******************** category queries ********************/

int apol_cat_get_by_query(const apol_policy_t * p, apol_cat_query_t * c, apol_vector_t ** v)
{
	qpol_iterator_t *iter;
	int retval = -1;
	*v = NULL;
	if (qpol_policy_get_cat_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_cat_t *cat;
		unsigned char isalias;
		if (qpol_iterator_get_item(iter, (void **)&cat) < 0 || qpol_cat_get_isalias(p->p, cat, &isalias) < 0) {
			goto cleanup;
		}
		if (isalias) {
			continue;
		}
		if (c != NULL) {
			int compval = apol_compare_cat(p,
						       cat, c->cat_name,
						       c->flags, &(c->regex));
			if (compval < 0) {
				goto cleanup;
			} else if (compval == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, cat)) {
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

apol_cat_query_t *apol_cat_query_create(void)
{
	return calloc(1, sizeof(apol_cat_query_t));
}

void apol_cat_query_destroy(apol_cat_query_t ** c)
{
	if (*c != NULL) {
		free((*c)->cat_name);
		apol_regex_destroy(&(*c)->regex);
		free(*c);
		*c = NULL;
	}
}

int apol_cat_query_set_cat(const apol_policy_t * p, apol_cat_query_t * c, const char *name)
{
	return apol_query_set(p, &c->cat_name, &c->regex, name);
}

int apol_cat_query_set_regex(const apol_policy_t * p, apol_cat_query_t * c, int is_regex)
{
	return apol_query_set_regex(p, &c->flags, is_regex);
}
