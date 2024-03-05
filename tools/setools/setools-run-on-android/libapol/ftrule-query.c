/**
 * @file
 *
 * Provides a way for setools to make queries about type enforcement
 * filename_transs within a policy.  The caller obtains a query object, fills in
 * its parameters, and then runs the query; it obtains a vector of
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
#include <string.h>

struct apol_filename_trans_query
{
	char *source, *target, *default_type, *name;
	apol_vector_t *classes;
	unsigned int flags;
};


/******************** filename_transition queries ********************/

int apol_filename_trans_get_by_query(const apol_policy_t * p, const apol_filename_trans_query_t * t, apol_vector_t ** v)
{
	apol_vector_t *source_list = NULL, *target_list = NULL, *class_list = NULL, *default_list = NULL;
	int retval = -1, source_as_any = 0, is_regex = 0;
	*v = NULL;
	qpol_iterator_t *iter = NULL;

	if (t != NULL) {
		is_regex = t->flags & APOL_QUERY_REGEX;
		if (t->source != NULL &&
		    (source_list =
		     apol_query_create_candidate_type_list(p, t->source, is_regex,
							   t->flags & APOL_QUERY_SOURCE_INDIRECT,
							   ((t->flags & (APOL_QUERY_SOURCE_TYPE | APOL_QUERY_SOURCE_ATTRIBUTE)) /
							    APOL_QUERY_SOURCE_TYPE))) == NULL) {
			goto cleanup;
		}

		if ((t->flags & APOL_QUERY_SOURCE_AS_ANY) && t->source != NULL) {
			default_list = target_list = source_list;
			source_as_any = 1;
		} else {
			if (t->target != NULL &&
			    (target_list =
			     apol_query_create_candidate_type_list(p, t->target, is_regex,
								   t->flags & APOL_QUERY_TARGET_INDIRECT,
								   ((t->
								     flags & (APOL_QUERY_TARGET_TYPE | APOL_QUERY_TARGET_ATTRIBUTE))
								    / APOL_QUERY_TARGET_TYPE))) == NULL) {
				goto cleanup;
			}
			if (t->default_type != NULL &&
			    (default_list =
			     apol_query_create_candidate_type_list(p, t->default_type, is_regex, 0,
								   APOL_QUERY_SYMBOL_IS_TYPE)) == NULL) {
				goto cleanup;
			}
		}
		if (t->classes != NULL &&
		    apol_vector_get_size(t->classes) > 0 &&
		    (class_list = apol_query_create_candidate_class_list(p, t->classes)) == NULL) {
			goto cleanup;
		}
	}

	if (qpol_policy_get_filename_trans_iter(p->p, &iter) < 0) {
		goto cleanup;
	}

	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}

	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		int match_source = 0, match_target = 0, match_default = 0;
		size_t i;

		qpol_filename_trans_t *filename_trans;
		if (qpol_iterator_get_item(iter, (void **)&filename_trans) < 0) {
			goto cleanup;
		}

		if (source_list == NULL) {
			match_source = 1;
		} else {
			const qpol_type_t *source_type;
			if (qpol_filename_trans_get_source_type(p->p, filename_trans, &source_type) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(source_list, source_type, NULL, NULL, &i) == 0) {
				match_source = 1;
			}
		}

		/* if source did not match, but treating source symbol
		 * as any field, then delay rejecting this filename_trans until
		 * the target and default have been checked */
		if (!source_as_any && !match_source) {
			continue;
		}

		if (target_list == NULL || (source_as_any && match_source)) {
			match_target = 1;
		} else {
			const qpol_type_t *target_type;
			if (qpol_filename_trans_get_target_type(p->p, filename_trans, &target_type) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(target_list, target_type, NULL, NULL, &i) == 0) {
				match_target = 1;
			}
		}

		if (!source_as_any && !match_target) {
			continue;
		}

		if (default_list == NULL || (source_as_any && match_source) || (source_as_any && match_target)) {
			match_default = 1;
		} else {
			const qpol_type_t *default_type;
			if (qpol_filename_trans_get_default_type(p->p, filename_trans, &default_type) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(default_list, default_type, NULL, NULL, &i) == 0) {
				match_default = 1;
			}
		}

		if (!source_as_any && !match_default) {
			continue;
		}
		/* at least one thing must match if source_as_any was given */
		if (source_as_any && (!match_source && !match_target && !match_default)) {
			continue;
		}

		if (class_list != NULL) {
			const qpol_class_t *obj_class;
			if (qpol_filename_trans_get_object_class(p->p, filename_trans, &obj_class) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(class_list, obj_class, NULL, NULL, &i) < 0) {
				continue;
			}
		}

		if (apol_vector_append(*v, filename_trans)) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	if (retval != 0) {
		apol_vector_destroy(v);
	}
	apol_vector_destroy(&source_list);
	if (!source_as_any) {
		apol_vector_destroy(&target_list);
		apol_vector_destroy(&default_list);
	}
	apol_vector_destroy(&class_list);
	qpol_iterator_destroy(&iter);
	return retval;
}

apol_filename_trans_query_t *apol_filename_trans_query_create(void)
{
	apol_filename_trans_query_t *t = calloc(1, sizeof(apol_filename_trans_query_t));
	if (t != NULL) {
		t->flags =
			(APOL_QUERY_SOURCE_TYPE | APOL_QUERY_SOURCE_ATTRIBUTE | APOL_QUERY_TARGET_TYPE |
			 APOL_QUERY_TARGET_ATTRIBUTE);
	}
	return t;
}

void apol_filename_trans_query_destroy(apol_filename_trans_query_t ** t)
{
	if (t != NULL && *t != NULL) {
		free((*t)->source);
		free((*t)->target);
		free((*t)->default_type);
		free((*t)->name);
		apol_vector_destroy(&(*t)->classes);
		free(*t);
		*t = NULL;
	}
}

int apol_filename_trans_query_set_source(const apol_policy_t * p, apol_filename_trans_query_t * t, const char *filename, int is_indirect)
{
	apol_query_set_flag(p, &t->flags, is_indirect, APOL_QUERY_SOURCE_INDIRECT);
	return apol_query_set(p, &t->source, NULL, filename);
}

//TODO is the equivilent terule_query_set_{source,target}_compoenent needed?

int apol_filename_trans_query_set_target(const apol_policy_t * p, apol_filename_trans_query_t * t, const char *type, int is_indirect)
{
	apol_query_set_flag(p, &t->flags, is_indirect, APOL_QUERY_TARGET_INDIRECT);
	return apol_query_set(p, &t->target, NULL, type);
}

int apol_filename_trans_query_set_default(const apol_policy_t * p, apol_filename_trans_query_t * t, const char *symbol)
{
	return apol_query_set(p, &t->default_type, NULL, symbol);
}

int apol_filename_trans_query_append_class(const apol_policy_t * p, apol_filename_trans_query_t * t, const char *obj_class)
{
	char *s = NULL;
	if (obj_class == NULL) {
		apol_vector_destroy(&t->classes);
	} else if ((s = strdup(obj_class)) == NULL || (t->classes == NULL && (t->classes = apol_vector_create(free)) == NULL)
		   || apol_vector_append(t->classes, s) < 0) {
		ERR(p, "%s", strerror(errno));
		free(s);
		return -1;
	}
	return 0;
}

int apol_filename_trans_query_set_name(const apol_policy_t * p, apol_filename_trans_query_t * t, const char *filename)
{
	return apol_query_set(p, &t->name, NULL, filename);
}

int apol_filename_trans_query_set_source_any(const apol_policy_t * p, apol_filename_trans_query_t * t, int is_any)
{
	return apol_query_set_flag(p, &t->flags, is_any, APOL_QUERY_SOURCE_AS_ANY);
}

int apol_filename_trans_query_set_regex(const apol_policy_t * p, apol_filename_trans_query_t * t, int is_regex)
{
	return apol_query_set_regex(p, &t->flags, is_regex);
}

char *apol_filename_trans_render(const apol_policy_t * policy, const qpol_filename_trans_t * filename_trans)
{
	char *tmp = NULL;
	const char *tmp_name = NULL;
	int error = 0;
	size_t tmp_sz = 0;
	const qpol_type_t *type = NULL;
	const qpol_class_t *obj_class = NULL;

	if (!policy || !filename_trans) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}

	/* source type */
	if (qpol_filename_trans_get_source_type(policy->p, filename_trans, &type)) {
		error = errno;
		goto err;
	}
	if (qpol_type_get_name(policy->p, type, &tmp_name)) {
		error = errno;
		goto err;
	}
	if (apol_str_appendf(&tmp, &tmp_sz, "type_transition %s ", tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	/* target type */
	if (qpol_filename_trans_get_target_type(policy->p, filename_trans, &type)) {
		error = errno;
		goto err;
	}
	if (qpol_type_get_name(policy->p, type, &tmp_name)) {
		error = errno;
		goto err;
	}
	if (apol_str_appendf(&tmp, &tmp_sz, "%s : ", tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	/* object class */
	if (qpol_filename_trans_get_object_class(policy->p, filename_trans, &obj_class)) {
		error = errno;
		goto err;
	}
	if (qpol_class_get_name(policy->p, obj_class, &tmp_name)) {
		error = errno;
		goto err;
	}
	if (apol_str_appendf(&tmp, &tmp_sz, "%s ", tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	/* default type */
	if (qpol_filename_trans_get_default_type(policy->p, filename_trans, &type)) {
		error = errno;
		goto err;
	}
	if (qpol_type_get_name(policy->p, type, &tmp_name)) {
		error = errno;
		goto err;
	}
	if (apol_str_appendf(&tmp, &tmp_sz, "%s", tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	/* filename */
	if (qpol_filename_trans_get_filename(policy->p, filename_trans, &tmp_name)) {
		error = errno;
		goto err;
	}

	if (apol_str_appendf(&tmp, &tmp_sz, " \"%s\";", tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	return tmp;

      err:
	free(tmp);
	errno = error;
	return NULL;
}
