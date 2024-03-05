/**
 * @file
 *
 * Provides a way for setools to make queries about different
 * components of a policy.  The caller obtains a query object, fills
 * in its parameters, and then runs the query; it obtains a vector of
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
#include <regex.h>
#include <stdlib.h>
#include <string.h>

/******************** misc helpers ********************/

void apol_regex_destroy(regex_t ** regex)
{
	if (*regex != NULL) {
		regfree(*regex);
		free(*regex);
		*regex = NULL;
	}
}

int apol_query_set(const apol_policy_t * p, char **query_name, regex_t ** regex, const char *name)
{
	if (*query_name != name) {
		if (regex != NULL) {
			apol_regex_destroy(regex);
		}
		free(*query_name);
		*query_name = NULL;
		if (name != NULL && name[0] != '\0' && ((*query_name) = strdup(name)) == NULL) {
			ERR(p, "%s", strerror(errno));
			return -1;
		}
	}
	return 0;
}

int apol_query_set_flag(const apol_policy_t * p __attribute__ ((unused)), unsigned int *flags, const int is_flag, int flag_value)
{
	if (is_flag) {
		*flags |= flag_value;
	} else {
		*flags &= ~flag_value;
	}
	return 0;
}

int apol_query_set_regex(const apol_policy_t * p, unsigned int *flags, const int is_regex)
{
	return apol_query_set_flag(p, flags, is_regex, APOL_QUERY_REGEX);
}

/********************* comparison helpers *********************/

int apol_compare(const apol_policy_t * p, const char *target, const char *name, unsigned int flags, regex_t ** regex)
{
	if (name == NULL || *name == '\0') {
		return 1;
	}
	char errbuf[1024] = { '\0' };
	if ((flags & APOL_QUERY_REGEX) && regex != NULL) {
		if (*regex == NULL) {
			if ((*regex = malloc(sizeof(**regex))) == NULL) {
				free(*regex);
				*regex = NULL;
				ERR(p, "%s", strerror(ENOMEM));
				return -1;
			}
			int regretv = regcomp(*regex, name, REG_EXTENDED | REG_NOSUB);
			if (regretv) {
				regerror(regretv, *regex, errbuf, 1024);
				free(*regex);
				*regex = NULL;
				ERR(p, "%s", errbuf);
				return -1;
			}
		}
		if (regexec(*regex, target, 0, NULL, 0) == 0) {
			return 1;
		}
		return 0;
	} else {
		if (strcmp(target, name) == 0) {
			return 1;
		}
		return 0;
	}
}

int apol_compare_iter(const apol_policy_t * p, qpol_iterator_t * iter,
		      const char *name, unsigned int flags, regex_t ** regex, int do_free)
{
	int compval;
	if (name == NULL || *name == '\0') {
		return 1;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		char *iter_name;
		if (qpol_iterator_get_item(iter, (void **)&iter_name) < 0) {
			return -1;
		}
		compval = apol_compare(p, iter_name, name, flags, regex);
		if (do_free)
			free(iter_name);
		if (compval != 0) {
			/* matched at least one name, or error */
			return compval;
		}
	}
	/* no matches */
	return 0;
}

int apol_compare_type(const apol_policy_t * p, const qpol_type_t * type, const char *name, unsigned int flags,
		      regex_t ** type_regex)
{
	const char *type_name;
	int compval;
	qpol_iterator_t *alias_iter = NULL;
	if (qpol_type_get_name(p->p, type, &type_name) < 0) {
		return -1;
	}
	compval = apol_compare(p, type_name, name, flags, type_regex);
	if (compval != 0) {
		return compval;
	}
	/* also check if the matches against one of the type's
	 * aliases */
	if (qpol_type_get_alias_iter(p->p, type, &alias_iter) < 0) {
		return -1;
	}
	compval = apol_compare_iter(p, alias_iter, name, flags, type_regex, 0);
	qpol_iterator_destroy(&alias_iter);
	return compval;
}

int apol_compare_permissive(const apol_policy_t * p, const qpol_permissive_t * permissive, const char *name, unsigned int flags,
		      regex_t ** permissive_regex)
{
	const char *permissive_name;
	int compval;
	
	if (qpol_permissive_get_name(p->p, permissive, &permissive_name) < 0) {
		return -1;
	}
	compval = apol_compare(p, permissive_name, name, flags, permissive_regex);
	
	return compval;
}

int apol_compare_polcap(const apol_policy_t * p, const qpol_polcap_t * polcap, const char *name, unsigned int flags,
		      regex_t ** polcap_regex)
{
	const char *polcap_name;
	int compval;
	
	if (qpol_polcap_get_name(p->p, polcap, &polcap_name) < 0) {
		return -1;
	}
	compval = apol_compare(p, polcap_name, name, flags, polcap_regex);
	
	return compval;
}

int apol_compare_cond_expr(const apol_policy_t * p, const qpol_cond_t * cond, const char *name, unsigned int flags,
			   regex_t ** bool_regex)
{
	qpol_iterator_t *expr_iter = NULL;
	int compval = -1;
	if (qpol_cond_get_expr_node_iter(p->p, cond, &expr_iter) < 0) {
		goto cleanup;
	}
	for (; !qpol_iterator_end(expr_iter); qpol_iterator_next(expr_iter)) {
		qpol_cond_expr_node_t *expr;
		uint32_t expr_type;
		qpol_bool_t *qbool;
		const char *bool_name;
		if (qpol_iterator_get_item(expr_iter, (void **)&expr) < 0 ||
		    qpol_cond_expr_node_get_expr_type(p->p, expr, &expr_type) < 0) {
			goto cleanup;
		}
		if (expr_type != QPOL_COND_EXPR_BOOL) {
			continue;
		}
		if (qpol_cond_expr_node_get_bool(p->p, expr, &qbool) < 0 || qpol_bool_get_name(p->p, qbool, &bool_name) < 0) {
			goto cleanup;
		}
		compval = apol_compare(p, bool_name, name, flags, bool_regex);
		if (compval != 0) {    /* catches both errors and success */
			goto cleanup;
		}
	}
	compval = 0;
      cleanup:
	qpol_iterator_destroy(&expr_iter);
	return compval;
}

int apol_compare_level(const apol_policy_t * p, const qpol_level_t * level, const char *name, unsigned int flags,
		       regex_t ** level_regex)
{
	const char *level_name;
	int compval;
	qpol_iterator_t *alias_iter = NULL;
	if (qpol_level_get_name(p->p, level, &level_name) < 0) {
		return -1;
	}
	compval = apol_compare(p, level_name, name, flags, level_regex);
	if (compval != 0) {
		return compval;
	}
	/* also check if the matches against one of the sensitivity's
	 * aliases */
	if (qpol_level_get_alias_iter(p->p, level, &alias_iter) < 0) {
		return -1;
	}
	compval = apol_compare_iter(p, alias_iter, name, flags, level_regex, 0);
	qpol_iterator_destroy(&alias_iter);
	return compval;
}

int apol_compare_cat(const apol_policy_t * p, const qpol_cat_t * cat, const char *name, unsigned int flags, regex_t ** cat_regex)
{
	const char *cat_name;
	int compval;
	qpol_iterator_t *alias_iter = NULL;
	if (qpol_cat_get_name(p->p, cat, &cat_name) < 0) {
		return -1;
	}
	compval = apol_compare(p, cat_name, name, flags, cat_regex);
	if (compval != 0) {
		return compval;
	}
	/* also check if the matches against one of the category's
	 * aliases */
	if (qpol_cat_get_alias_iter(p->p, cat, &alias_iter) < 0) {
		return -1;
	}
	compval = apol_compare_iter(p, alias_iter, name, flags, cat_regex, 0);
	qpol_iterator_destroy(&alias_iter);
	return compval;
}

int apol_compare_context(const apol_policy_t * p, const qpol_context_t * target, const apol_context_t * search, unsigned int flags)
{
	apol_context_t *apol_context;
	int retval;
	if (search == NULL) {
		return 1;
	}
	apol_context = apol_context_create_from_qpol_context(p, target);
	retval = apol_context_compare(p, apol_context, search, flags);
	apol_context_destroy(&apol_context);
	return retval;
}

/******************** other helpers ********************/

int apol_query_get_type(const apol_policy_t * p, const char *type_name, const qpol_type_t ** type)
{
	unsigned char isalias;
	if (qpol_policy_get_type_by_name(p->p, type_name, type) < 0 || qpol_type_get_isalias(p->p, *type, &isalias) < 0) {
		return -1;
	}
	if (isalias) {
		const char *primary_name;
		if (qpol_type_get_name(p->p, *type, &primary_name) < 0 ||
		    qpol_policy_get_type_by_name(p->p, primary_name, type) < 0) {
			return -1;
		}
	}
	return 0;
}

/**
 * Append a non-aliased type to a vector.  If the passed in type is an
 * alias, find its primary type and append that instead.
 *
 * @param p Policy in which to look up types.
 * @param v Vector in which append the non-aliased type.
 * @param type Type or attribute to append.  If this is an alias,
 * append its primary.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_query_append_type(const apol_policy_t * p, apol_vector_t * v, const qpol_type_t * type)
{
	unsigned char isalias;
	const qpol_type_t *real_type = type;
	if (qpol_type_get_isalias(p->p, type, &isalias) < 0) {
		return -1;
	}
	if (isalias) {
		const char *primary_name;
		if (qpol_type_get_name(p->p, type, &primary_name) < 0 ||
		    qpol_policy_get_type_by_name(p->p, primary_name, &real_type) < 0) {
			return -1;
		}
	}
	if (apol_vector_append(v, (void *)real_type) < 0) {
		ERR(p, "%s", strerror(ENOMEM));
		return -1;
	}
	return 0;
}

apol_vector_t *apol_query_create_candidate_type_list(const apol_policy_t * p, const char *symbol, int do_regex, int do_indirect,
						     unsigned int ta_flag)
{
	apol_vector_t *list = apol_vector_create(NULL);
	const qpol_type_t *type;
	regex_t *regex = NULL;
	qpol_iterator_t *iter = NULL, *alias_iter = NULL;
	int retval = -1, error = 0;
	unsigned char isalias, isattr;
	const char *type_name;
	int compval;
	size_t i, orig_vector_size;

	if (list == NULL) {
		error = EINVAL;
		ERR(p, "%s", strerror(error));
		goto cleanup;
	}

	if (ta_flag == 0 || (ta_flag & ~APOL_QUERY_SYMBOL_IS_BOTH)) {
		error = EINVAL;
		ERR(p, "%s", strerror(error));
		goto cleanup;
	}

	if (!do_regex && apol_query_get_type(p, symbol, &type) == 0) {
		if (apol_query_append_type(p, list, type) < 0) {
			error = errno;
			goto cleanup;
		}
	}

	if (do_regex) {
		if (qpol_policy_get_type_iter(p->p, &iter) < 0) {
			error = errno;
			goto cleanup;
		}
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&type) < 0 || qpol_type_get_name(p->p, type, &type_name) < 0) {
				error = errno;
				goto cleanup;
			}
			compval = apol_compare(p, type_name, symbol, APOL_QUERY_REGEX, &regex);
			if (compval < 0) {
				error = errno;
				goto cleanup;
			}
			if (compval && apol_query_append_type(p, list, type)) {
				error = errno;
				goto cleanup;
			}
			if (compval)
				continue;
			if (qpol_type_get_alias_iter(p->p, type, &alias_iter) < 0) {
				error = errno;
				goto cleanup;
			}
			for (; !qpol_iterator_end(alias_iter); qpol_iterator_next(alias_iter)) {
				if (qpol_iterator_get_item(alias_iter, (void **)&type_name) < 0) {
					error = errno;
					goto cleanup;
				}
				compval = apol_compare(p, type_name, symbol, APOL_QUERY_REGEX, &regex);
				if (compval < 0) {
					error = errno;
					goto cleanup;
				}
				if (compval && apol_query_append_type(p, list, type)) {
					error = errno;
					goto cleanup;
				}
				if (compval)
					break;
			}
			qpol_iterator_destroy(&alias_iter);
		}
		qpol_iterator_destroy(&iter);
	}

	/* prune to match ta_flag */
	for (i = 0; i < apol_vector_get_size(list); i++) {
		type = (qpol_type_t *) apol_vector_get_element(list, i);
		if (qpol_type_get_isattr(p->p, type, &isattr) < 0) {
			error = errno;
			goto cleanup;
		}
		if ((isattr && !(ta_flag & APOL_QUERY_SYMBOL_IS_ATTRIBUTE)) || (!isattr && !(ta_flag & APOL_QUERY_SYMBOL_IS_TYPE))) {
			apol_vector_remove(list, i);
			i--;
		}
	}

	if (do_indirect) {
		orig_vector_size = apol_vector_get_size(list);
		for (i = 0; i < orig_vector_size; i++) {
			type = (qpol_type_t *) apol_vector_get_element(list, i);
			if (qpol_type_get_isalias(p->p, type, &isalias) < 0 || qpol_type_get_isattr(p->p, type, &isattr) < 0) {
				error = errno;
				goto cleanup;
			}
			if (isalias) {
				continue;
			}
			if ((isattr &&
			     qpol_type_get_type_iter(p->p, type, &iter) < 0) ||
			    (!isattr && qpol_type_get_attr_iter(p->p, type, &iter) < 0)) {
				error = errno;
				goto cleanup;
			}
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				if (qpol_iterator_get_item(iter, (void **)&type) < 0) {
					error = errno;
					goto cleanup;
				}
				if (apol_query_append_type(p, list, type)) {
					error = errno;
					goto cleanup;
				}
			}
			qpol_iterator_destroy(&iter);
		}
	}

	apol_vector_sort_uniquify(list, NULL, NULL);
	retval = 0;
      cleanup:
	if (regex != NULL) {
		regfree(regex);
		free(regex);
	}
	qpol_iterator_destroy(&iter);
	qpol_iterator_destroy(&alias_iter);
	if (retval < 0) {
		apol_vector_destroy(&list);
		errno = error;
	}
	return list;
}

apol_vector_t *apol_query_create_candidate_syn_type_list(const apol_policy_t * p, const char *symbol, int do_regex, int do_indirect,
							 unsigned int ta_flag)
{
	apol_vector_t *list = apol_vector_create(NULL);
	const qpol_type_t *type;
	regex_t *regex = NULL;
	qpol_iterator_t *iter = NULL, *alias_iter = NULL;
	int retval = -1, error = 0;
	unsigned char isalias, isattr;
	const char *type_name;
	int compval;
	size_t i, orig_vector_size;

	if (list == NULL) {
		error = EINVAL;
		ERR(p, "%s", strerror(error));
		goto cleanup;
	}

	if (!p || !qpol_policy_has_capability(apol_policy_get_qpol(p), QPOL_CAP_ATTRIB_NAMES)
	    || !qpol_policy_has_capability(apol_policy_get_qpol(p), QPOL_CAP_SYN_RULES)) {
		error = EINVAL;
		ERR(p, "%s", strerror(error));
		goto cleanup;
	}

	if (ta_flag == 0 || (ta_flag & ~APOL_QUERY_SYMBOL_IS_BOTH)) {
		error = EINVAL;
		ERR(p, "%s", strerror(error));
		goto cleanup;
	}

	if (!do_regex && apol_query_get_type(p, symbol, &type) == 0) {
		if (apol_query_append_type(p, list, type) < 0) {
			error = errno;
			goto cleanup;
		}
	}

	if (do_regex) {
		if (qpol_policy_get_type_iter(p->p, &iter) < 0) {
			error = errno;
			goto cleanup;
		}
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&type) < 0 || qpol_type_get_name(p->p, type, &type_name) < 0) {
				error = errno;
				goto cleanup;
			}
			compval = apol_compare(p, type_name, symbol, APOL_QUERY_REGEX, &regex);
			if (compval < 0) {
				error = errno;
				goto cleanup;
			}
			if (compval && apol_query_append_type(p, list, type)) {
				error = errno;
				goto cleanup;
			}
			if (compval)
				continue;
			if (qpol_type_get_alias_iter(p->p, type, &alias_iter) < 0) {
				error = errno;
				goto cleanup;
			}
			for (; !qpol_iterator_end(alias_iter); qpol_iterator_next(alias_iter)) {
				if (qpol_iterator_get_item(alias_iter, (void **)&type_name) < 0) {
					error = errno;
					goto cleanup;
				}
				compval = apol_compare(p, type_name, symbol, APOL_QUERY_REGEX, &regex);
				if (compval < 0) {
					error = errno;
					goto cleanup;
				}
				if (compval && apol_query_append_type(p, list, type)) {
					error = errno;
					goto cleanup;
				}
				if (compval)
					break;
			}
			qpol_iterator_destroy(&alias_iter);
		}
		qpol_iterator_destroy(&iter);
	}

	/* prune to match ta_flag */
	for (i = 0; i < apol_vector_get_size(list); i++) {
		type = (qpol_type_t *) apol_vector_get_element(list, i);
		if (qpol_type_get_isattr(p->p, type, &isattr) < 0) {
			error = errno;
			goto cleanup;
		}
		if ((isattr && !(ta_flag & APOL_QUERY_SYMBOL_IS_ATTRIBUTE)) || (!isattr && !(ta_flag & APOL_QUERY_SYMBOL_IS_TYPE))) {
			apol_vector_remove(list, i);
			i--;
		}
	}

	orig_vector_size = apol_vector_get_size(list);
	for (i = 0; i < orig_vector_size; i++) {
		type = (qpol_type_t *) apol_vector_get_element(list, i);
		if (qpol_type_get_isalias(p->p, type, &isalias) < 0 || qpol_type_get_isattr(p->p, type, &isattr) < 0) {
			error = errno;
			goto cleanup;
		}
		if (isalias) {
			continue;
		}
		if (!do_indirect && !isattr)
			continue;
		if ((isattr && qpol_type_get_type_iter(p->p, type, &iter) < 0) ||
		    (!isattr && qpol_type_get_attr_iter(p->p, type, &iter) < 0)) {
			error = errno;
			goto cleanup;
		}
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&type) < 0) {
				error = errno;
				goto cleanup;
			}
			if (apol_query_append_type(p, list, type)) {
				error = errno;
				goto cleanup;
			}
		}
		qpol_iterator_destroy(&iter);
	}

	apol_vector_sort_uniquify(list, NULL, NULL);
	retval = 0;
      cleanup:
	if (regex != NULL) {
		regfree(regex);
		free(regex);
	}
	qpol_iterator_destroy(&iter);
	qpol_iterator_destroy(&alias_iter);
	if (retval < 0) {
		apol_vector_destroy(&list);
		list = NULL;
		errno = error;
	}
	return list;
}

apol_vector_t *apol_query_create_candidate_role_list(const apol_policy_t * p, char *symbol, int do_regex)
{
	apol_vector_t *list = apol_vector_create(NULL);
	const qpol_role_t *role;
	regex_t *regex = NULL;
	qpol_iterator_t *iter = NULL;
	int retval = -1;

	if (list == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}

	if (!do_regex && qpol_policy_get_role_by_name(p->p, symbol, &role) == 0) {
		if (apol_vector_append(list, (void *)role) < 0) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}

	if (do_regex) {
		if (qpol_policy_get_role_iter(p->p, &iter) < 0) {
			goto cleanup;
		}
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			const char *role_name;
			int compval;
			if (qpol_iterator_get_item(iter, (void **)&role) < 0 || qpol_role_get_name(p->p, role, &role_name) < 0) {
				goto cleanup;
			}
			compval = apol_compare(p, role_name, symbol, APOL_QUERY_REGEX, &regex);
			if (compval < 0) {
				goto cleanup;
			}
			if (compval && apol_vector_append(list, (void *)role)) {
				ERR(p, "%s", strerror(ENOMEM));
				goto cleanup;
			}
		}
		qpol_iterator_destroy(&iter);
	}
	apol_vector_sort_uniquify(list, NULL, NULL);
	retval = 0;
      cleanup:
	if (regex != NULL) {
		regfree(regex);
		free(regex);
	}
	qpol_iterator_destroy(&iter);
	if (retval < 0) {
		apol_vector_destroy(&list);
		list = NULL;
	}
	return list;
}

apol_vector_t *apol_query_create_candidate_class_list(const apol_policy_t * p, apol_vector_t * classes)
{
	apol_vector_t *list = apol_vector_create(NULL);
	size_t i;
	int retval = -1;

	if (list == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}

	for (i = 0; i < apol_vector_get_size(classes); i++) {
		char *class_string = (char *)apol_vector_get_element(classes, i);
		const qpol_class_t *class;
		if (qpol_policy_get_class_by_name(p->p, class_string, &class) == 0) {
			if (apol_vector_append(list, (void *)class) < 0) {
				ERR(p, "%s", strerror(ENOMEM));
				goto cleanup;
			}
		}
	}
	apol_vector_sort_uniquify(list, NULL, NULL);
	retval = 0;
      cleanup:
	if (retval < 0) {
		apol_vector_destroy(&list);
		list = NULL;
	}
	return list;
}

apol_vector_t *apol_query_expand_type(const apol_policy_t * p, const qpol_type_t * t)
{
	apol_vector_t *v = NULL;
	int retval = -1;
	unsigned char isattr;
	qpol_iterator_t *iter = NULL;

	if ((v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	if (qpol_type_get_isattr(p->p, t, &isattr) < 0) {
		goto cleanup;
	}
	if (!isattr) {
		if (apol_vector_append(v, (void *)t) < 0) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	} else {
		if (qpol_type_get_type_iter(p->p, t, &iter) < 0) {
			goto cleanup;
		}
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			qpol_type_t *type;
			if (qpol_iterator_get_item(iter, (void **)&type) < 0) {
				goto cleanup;
			}
			if (apol_vector_append(v, type) < 0) {
				ERR(p, "%s", strerror(ENOMEM));
				goto cleanup;
			}
		}
	}
	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
	if (retval != 0) {
		apol_vector_destroy(&v);
		return NULL;
	}
	return v;
}

/******** apol_obj_perm - set of an object with a list of permissions ********/

struct apol_obj_perm
{
	char *obj_class;	       /* name of object class */
	apol_vector_t *perms;	       /* vector of permission names */
};

apol_obj_perm_t *apol_obj_perm_create(void)
{
	apol_obj_perm_t *op = calloc(1, sizeof(apol_obj_perm_t));
	if (!op)
		return NULL;

	op->perms = apol_vector_create(free);
	if (!(op->perms)) {
		free(op);
		return NULL;
	}

	return op;
}

void apol_obj_perm_free(void *op)
{
	apol_obj_perm_t *inop = (apol_obj_perm_t *) op;
	if (inop != NULL) {
		free(inop->obj_class);
		apol_vector_destroy(&inop->perms);
		free(inop);
	}
}

int apol_obj_perm_set_obj_name(apol_obj_perm_t * op, const char *obj_name)
{
	char *tmp = NULL;

	if (!op) {
		errno = EINVAL;
		return -1;
	}

	if (obj_name) {
		if (!(tmp = strdup(obj_name)))
			return -1;
		free(op->obj_class);
		op->obj_class = tmp;
	} else {
		free(op->obj_class);
		op->obj_class = NULL;
	}

	return 0;
}

char *apol_obj_perm_get_obj_name(const apol_obj_perm_t * op)
{
	if (!op) {
		errno = EINVAL;
		return NULL;
	}

	return op->obj_class;
}

int apol_obj_perm_append_perm(apol_obj_perm_t * op, const char *perm)
{
	char *tmp = NULL;

	if (!op) {
		errno = EINVAL;
		return -1;
	}

	if (perm) {
		if ((tmp = strdup(perm)) == NULL || (op->perms == NULL && (op->perms = apol_vector_create(free)) == NULL)) {
			free(tmp);
			return -1;
		}
		if (apol_vector_append_unique(op->perms, tmp, apol_str_strcmp, NULL) < 0) {
			free(tmp);
			return -1;
		}
	} else {
		apol_vector_destroy(&op->perms);
	}

	return 0;
}

apol_vector_t *apol_obj_perm_get_perm_vector(const apol_obj_perm_t * op)
{
	if (!op) {
		errno = EINVAL;
		return NULL;
	}

	return op->perms;
}

int apol_obj_perm_compare_class(const void *a, const void *b, void *policy)
{
	const apol_obj_perm_t *opa = (const apol_obj_perm_t *)a;
	const apol_obj_perm_t *opb = (const apol_obj_perm_t *)b;
	apol_policy_t *p = (apol_policy_t *) policy;
	const qpol_class_t *obja = NULL, *objb = NULL;
	uint32_t a_val = 0, b_val = 0;

	qpol_policy_get_class_by_name(p->p, opa->obj_class, &obja);
	qpol_policy_get_class_by_name(p->p, opb->obj_class, &objb);
	qpol_class_get_value(p->p, obja, &a_val);
	qpol_class_get_value(p->p, objb, &b_val);

	return (int)(a_val - b_val);
}

int apol_query_type_set_uses_types_directly(const apol_policy_t * p, const qpol_type_set_t * set, const apol_vector_t * v)
{
	qpol_iterator_t *iter = NULL;
	qpol_type_t *type = NULL;
	size_t i;
	uint32_t comp;

	if (!p || !set) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (!v || !apol_vector_get_size(v))
		return 0;

	if (qpol_type_set_get_is_comp(p->p, set, &comp)) {
		return -1;
	}
	if (comp) {
		if (qpol_type_set_get_subtracted_types_iter(p->p, set, &iter)) {
			return -1;
		}
	} else {
		if (qpol_type_set_get_included_types_iter(p->p, set, &iter)) {
			return -1;
		}
	}

	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_iterator_get_item(iter, (void **)&type);
		if (!apol_vector_get_index(v, (void *)type, NULL, NULL, &i)) {
			qpol_iterator_destroy(&iter);
			return 1;
		}
	}
	qpol_iterator_destroy(&iter);

	return 0;
}
