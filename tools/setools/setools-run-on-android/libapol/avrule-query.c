/**
 * @file
 *
 * Provides a way for setools to make queries about access vector
 * rules within a policy.  The caller obtains a query object, fills in
 * its parameters, and then runs the query; it obtains a vector of
 * results.  Searches are conjunctive -- all fields of the search
 * query must match for a datum to be added to the results query.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006-2008 Tresys Technology, LLC
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
#include <apol/bst.h>
#include <qpol/policy_extend.h>
#include <errno.h>
#include <string.h>

struct apol_avrule_query
{
	char *source, *target, *bool_name;
	apol_vector_t *classes, *perms;
	unsigned int rules;
	unsigned int flags;
};

/**
 *  Common semantic rule selection routine used in get*rule_by_query.
 *  @param p Policy to search.
 *  @param v Vector of rules to populate (of type qpol_avrule_t).
 *  @param rule_type Mask of rules to search.
 *  @param flags Query options as specified by the apol_avrule_query.
 *  @param source_list If non-NULL, list of types to use as source.
 *  If NULL, accept all types.
 *  @param target_list If non-NULL, list of types to use as target.
 *  If NULL, accept all types.
 *  @param class_list If non-NULL, list of classes to use.
 *  If NULL, accept all classes.
 *  @param perm_list If non-NULL, list of permisions to use.
 *  If NULL, accept all permissions.
 *  @param bool_name If non-NULL, find conditional rules affected by this boolean.
 *  If NULL, all rules will be considered (including unconditional rules).
 *  @return 0 on success and < 0 on failure.
 */
static int rule_select(const apol_policy_t * p, apol_vector_t * v, uint32_t rule_type, unsigned int flags,
		       const apol_vector_t * source_list, const apol_vector_t * target_list, const apol_vector_t * class_list,
		       const apol_vector_t * perm_list, const char *bool_name)
{
	qpol_iterator_t *iter = NULL, *perm_iter = NULL;
	const int only_enabled = flags & APOL_QUERY_ONLY_ENABLED;
	const int is_regex = flags & APOL_QUERY_REGEX;
	const int source_as_any = flags & APOL_QUERY_SOURCE_AS_ANY;
	size_t num_perms_to_match = 1;
	int retv = -1;
	regex_t *bool_regex = NULL;

	if ((flags & APOL_QUERY_MATCH_ALL_PERMS) && perm_list != NULL) {
		num_perms_to_match = apol_vector_get_size(perm_list);
	}
	if (qpol_policy_get_avrule_iter(p->p, rule_type, &iter) < 0) {
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_avrule_t *rule;
		uint32_t is_enabled;
		const qpol_cond_t *cond = NULL;
		int match_source = 0, match_target = 0, match_bool = 0;
		size_t match_perm = 0, i;
		if (qpol_iterator_get_item(iter, (void **)&rule) < 0) {
			goto cleanup;
		}

		if (qpol_avrule_get_is_enabled(p->p, rule, &is_enabled) < 0) {
			goto cleanup;
		}
		if (!is_enabled && only_enabled) {
			continue;
		}

		if (bool_name != NULL) {
			if (qpol_avrule_get_cond(p->p, rule, &cond) < 0) {
				goto cleanup;
			}
			if (cond == NULL) {
				continue;	/* skip unconditional rule */
			}
			match_bool = apol_compare_cond_expr(p, cond, bool_name, is_regex, &bool_regex);
			if (match_bool < 0) {
				goto cleanup;
			} else if (match_bool == 0) {
				continue;
			}
		}

		if (source_list == NULL) {
			match_source = 1;
		} else {
			const qpol_type_t *source_type;
			if (qpol_avrule_get_source_type(p->p, rule, &source_type) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(source_list, source_type, NULL, NULL, &i) == 0) {
				match_source = 1;
			}
		}

		/* if source did not match, but treating source symbol
		 * as any field, then delay rejecting this rule until
		 * the target has been checked */
		if (!source_as_any && !match_source) {
			continue;
		}

		if (target_list == NULL || (source_as_any && match_source)) {
			match_target = 1;
		} else {
			const qpol_type_t *target_type;
			if (qpol_avrule_get_target_type(p->p, rule, &target_type) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(target_list, target_type, NULL, NULL, &i) == 0) {
				match_target = 1;
			}
		}

		if (!match_target) {
			continue;
		}

		if (class_list != NULL) {
			const qpol_class_t *obj_class;
			if (qpol_avrule_get_object_class(p->p, rule, &obj_class) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(class_list, obj_class, NULL, NULL, &i) < 0) {
				continue;
			}
		}

		if (perm_list != NULL) {
			for (i = 0; i < apol_vector_get_size(perm_list) && match_perm < num_perms_to_match; i++) {
				char *perm = (char *)apol_vector_get_element(perm_list, i);
				if (qpol_avrule_get_perm_iter(p->p, rule, &perm_iter) < 0) {
					goto cleanup;
				}
				int match = apol_compare_iter(p, perm_iter, perm, 0, NULL, 1);
				if (match < 0) {
					goto cleanup;
				} else if (match > 0) {
					match_perm++;
				}
				qpol_iterator_destroy(&perm_iter);
			}
		} else {
			match_perm = num_perms_to_match;
		}
		if (match_perm < num_perms_to_match) {
			continue;
		}

		if (apol_vector_append(v, rule)) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}

	retv = 0;
      cleanup:
	apol_regex_destroy(&bool_regex);
	qpol_iterator_destroy(&iter);
	qpol_iterator_destroy(&perm_iter);
	return retv;
}

int apol_avrule_get_by_query(const apol_policy_t * p, const apol_avrule_query_t * a, apol_vector_t ** v)
{
	apol_vector_t *source_list = NULL, *target_list = NULL, *class_list = NULL, *perm_list = NULL;
	int retval = -1, source_as_any = 0, is_regex = 0;
	char *bool_name = NULL;
	*v = NULL;
	unsigned int flags = 0;

	uint32_t rule_type = QPOL_RULE_ALLOW | QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT;
//	if (qpol_policy_has_capability(apol_policy_get_qpol(p), QPOL_CAP_NEVERALLOW)) {
		rule_type |= QPOL_RULE_NEVERALLOW;
//	}
	if (a != NULL) {
		if (a->rules != 0) {
			rule_type &= a->rules;
		}
		flags = a->flags;
		is_regex = a->flags & APOL_QUERY_REGEX;
		bool_name = a->bool_name;
		if (a->source != NULL &&
		    (source_list =
		     apol_query_create_candidate_type_list(p, a->source, is_regex,
							   a->flags & APOL_QUERY_SOURCE_INDIRECT,
							   ((a->flags & (APOL_QUERY_SOURCE_TYPE | APOL_QUERY_SOURCE_ATTRIBUTE)) /
							    APOL_QUERY_SOURCE_TYPE))) == NULL) {
			goto cleanup;
		}
		if ((a->flags & APOL_QUERY_SOURCE_AS_ANY) && a->source != NULL) {
			target_list = source_list;
			source_as_any = 1;
		} else if (a->target != NULL &&
			   (target_list =
			    apol_query_create_candidate_type_list(p, a->target, is_regex,
								  a->flags & APOL_QUERY_TARGET_INDIRECT,
								  ((a->
								    flags & (APOL_QUERY_TARGET_TYPE | APOL_QUERY_TARGET_ATTRIBUTE))
								   / APOL_QUERY_TARGET_TYPE))) == NULL) {
			goto cleanup;
		}
		if (a->classes != NULL &&
		    apol_vector_get_size(a->classes) > 0 &&
		    (class_list = apol_query_create_candidate_class_list(p, a->classes)) == NULL) {
			goto cleanup;
		}
		if (a->perms != NULL && apol_vector_get_size(a->perms) > 0) {
			perm_list = a->perms;
		}
	}

	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}

	if (rule_select(p, *v, rule_type, flags, source_list, target_list, class_list, perm_list, bool_name)) {
		goto cleanup;
	}

	retval = 0;
      cleanup:
	if (retval != 0) {
		apol_vector_destroy(v);
	}
	apol_vector_destroy(&source_list);
	if (!source_as_any) {
		apol_vector_destroy(&target_list);
	}
	apol_vector_destroy(&class_list);
	/* don't destroy perm_list - it points to query's permission list */
	return retval;
}

int apol_syn_avrule_get_by_query(const apol_policy_t * p, const apol_avrule_query_t * a, apol_vector_t ** v)
{
	qpol_iterator_t *iter = NULL, *perm_iter = NULL;
	apol_vector_t *source_list = NULL, *target_list = NULL, *class_list = NULL, *perm_list = NULL, *syn_v = NULL;
	apol_vector_t *target_types_list = NULL;
	int retval = -1, source_as_any = 0, is_regex = 0;
	char *bool_name = NULL;
	regex_t *bool_regex = NULL;
	*v = NULL;
	size_t i;
	unsigned int flags = 0;

	if (!p || !qpol_policy_has_capability(apol_policy_get_qpol(p), QPOL_CAP_SYN_RULES)) {
		ERR(p, "%s", strerror(EINVAL));
		goto cleanup;
	}

	uint32_t rule_type = QPOL_RULE_ALLOW | QPOL_RULE_NEVERALLOW | QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT;
	if (a != NULL) {
		if (a->rules != 0) {
			rule_type &= a->rules;
		}
		flags = a->flags;
		is_regex = a->flags & APOL_QUERY_REGEX;
		bool_name = a->bool_name;
		if (a->source != NULL &&
		    (source_list =
		     apol_query_create_candidate_syn_type_list(p, a->source, is_regex,
							       a->flags & APOL_QUERY_SOURCE_INDIRECT,
							       ((a->flags & (APOL_QUERY_SOURCE_TYPE |
									     APOL_QUERY_SOURCE_ATTRIBUTE)) /
								APOL_QUERY_SOURCE_TYPE))) == NULL) {
			goto cleanup;
		}
		if ((a->flags & APOL_QUERY_SOURCE_AS_ANY) && a->source != NULL) {
			target_list = source_list;
			source_as_any = 1;
		} else if (a->target != NULL &&
			   (target_list =
			    apol_query_create_candidate_syn_type_list(p, a->target, is_regex,
								      a->flags & APOL_QUERY_TARGET_INDIRECT,
								      ((a->flags & (APOL_QUERY_TARGET_TYPE |
										    APOL_QUERY_TARGET_ATTRIBUTE))
								       / APOL_QUERY_TARGET_TYPE))) == NULL) {
			goto cleanup;
		}
		if (a->classes != NULL &&
		    apol_vector_get_size(a->classes) > 0 &&
		    (class_list = apol_query_create_candidate_class_list(p, a->classes)) == NULL) {
			goto cleanup;
		}
		if (a->perms != NULL && apol_vector_get_size(a->perms) > 0) {
			perm_list = a->perms;
		}
	}

	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}

	if (rule_select(p, *v, rule_type, flags, source_list, target_list, class_list, perm_list, bool_name)) {
		goto cleanup;
	}

	syn_v = apol_avrule_list_to_syn_avrules(p, *v, perm_list);
	if (!syn_v) {
		goto cleanup;
	}
	apol_vector_destroy(v);
	*v = syn_v;
	syn_v = NULL;

	/* if both fields are indirect skip post filtering type sets */
	if ((a->flags & APOL_QUERY_SOURCE_INDIRECT) && (a->flags & (APOL_QUERY_TARGET_INDIRECT | APOL_QUERY_SOURCE_AS_ANY))) {
		retval = 0;
		goto cleanup;
	}
	/* if not searching by source or target we are done */
	if (!source_list && !target_list) {
		retval = 0;
		goto cleanup;
	}

	if (source_list && !(a->flags & APOL_QUERY_SOURCE_INDIRECT)) {
		apol_vector_destroy(&source_list);
		source_list =
			apol_query_create_candidate_type_list(p, a->source, is_regex, 0,
							      ((a->flags & (APOL_QUERY_SOURCE_TYPE | APOL_QUERY_SOURCE_ATTRIBUTE)) /
							       APOL_QUERY_SOURCE_TYPE));
		if (!source_list)
			goto cleanup;
	}
	if (target_list && (source_as_any || !(a->flags & APOL_QUERY_TARGET_INDIRECT))) {
		if (source_as_any) {
			target_list = source_list;
		} else {
			apol_vector_destroy(&target_list);
			target_list =
				apol_query_create_candidate_type_list(p, a->target, is_regex, 0,
								      ((a->flags & (APOL_QUERY_SOURCE_TYPE |
										    APOL_QUERY_SOURCE_ATTRIBUTE)) /
								       APOL_QUERY_SOURCE_TYPE));
			if (!target_list)
				goto cleanup;
		}
	}
	if (target_list) {
		target_types_list = apol_vector_create_from_vector(target_list, NULL, NULL, NULL);
		if (!target_types_list) {
			ERR(p, "%s", strerror(errno));
			goto cleanup;
		}
		qpol_type_t *type = NULL;
		for (i = 0; i < apol_vector_get_size(target_types_list); i++) {
			type = apol_vector_get_element(target_types_list, i);
			unsigned char isattr = 0;
			qpol_type_get_isattr(p->p, type, &isattr);
			if (isattr) {
				apol_vector_remove(target_types_list, i);
				i--;
			}
		}
	}
	for (i = 0; i < apol_vector_get_size(*v); i++) {
		qpol_syn_avrule_t *srule = apol_vector_get_element(*v, i);
		const qpol_type_set_t *stypes = NULL, *ttypes = NULL;
		int uses_source = 0, uses_target = 0;
		uint32_t is_self = 0;
		qpol_syn_avrule_get_source_type_set(p->p, srule, &stypes);
		qpol_syn_avrule_get_target_type_set(p->p, srule, &ttypes);
		qpol_syn_avrule_get_is_target_self(p->p, srule, &is_self);
		if (source_list && !(a->flags & APOL_QUERY_SOURCE_INDIRECT)) {
			uses_source = apol_query_type_set_uses_types_directly(p, stypes, source_list);
			if (uses_source < 0)
				goto cleanup;
		} else if (source_list && a->flags & APOL_QUERY_SOURCE_INDIRECT) {
			uses_source = 1;
		} else if (!source_list) {
			uses_source = 1;
		}

		if (target_list
		    && !((a->flags & APOL_QUERY_TARGET_INDIRECT) || (source_as_any && a->flags & APOL_QUERY_SOURCE_INDIRECT))) {
			uses_target = apol_query_type_set_uses_types_directly(p, ttypes, target_list);
			if (uses_target < 0)
				goto cleanup;
			if (is_self) {
				uses_target |= apol_query_type_set_uses_types_directly(p, stypes, target_types_list);
				if (uses_target < 0)
					goto cleanup;
			}
		} else if (target_list && ((a->flags & APOL_QUERY_TARGET_INDIRECT)
					   || (source_as_any && a->flags & APOL_QUERY_SOURCE_INDIRECT))) {
			uses_target = 1;
		} else if (!target_list) {
			uses_target = 1;
		}

		if (!((uses_source && uses_target) || (source_as_any && (uses_source || uses_target)))) {
			apol_vector_remove(*v, i);
			i--;
		}
	}

	retval = 0;
      cleanup:
	if (retval != 0) {
		apol_vector_destroy(v);
	}
	apol_vector_destroy(&syn_v);
	apol_vector_destroy(&source_list);
	apol_vector_destroy(&target_types_list);
	if (!source_as_any) {
		apol_vector_destroy(&target_list);
	}
	apol_vector_destroy(&class_list);
	/* don't destroy perm_list - it points to query's permission list */
	apol_regex_destroy(&bool_regex);
	qpol_iterator_destroy(&iter);
	qpol_iterator_destroy(&perm_iter);
	return retval;
}

apol_avrule_query_t *apol_avrule_query_create(void)
{
	apol_avrule_query_t *a = calloc(1, sizeof(apol_avrule_query_t));
	if (a != NULL) {
		a->rules = ~0U;
		a->flags =
			(APOL_QUERY_SOURCE_TYPE | APOL_QUERY_SOURCE_ATTRIBUTE | APOL_QUERY_TARGET_TYPE |
			 APOL_QUERY_TARGET_ATTRIBUTE);
	}
	return a;
}

void apol_avrule_query_destroy(apol_avrule_query_t ** a)
{
	if (*a != NULL) {
		free((*a)->source);
		free((*a)->target);
		free((*a)->bool_name);
		apol_vector_destroy(&(*a)->classes);
		apol_vector_destroy(&(*a)->perms);
		free(*a);
		*a = NULL;
	}
}

int apol_avrule_query_set_rules(const apol_policy_t * p __attribute__ ((unused)), apol_avrule_query_t * a, unsigned int rules)
{
	if (rules != 0) {
		a->rules = rules;
	} else {
		a->rules = ~0U;
	}
	return 0;
}

int apol_avrule_query_set_source(const apol_policy_t * p, apol_avrule_query_t * a, const char *symbol, int is_indirect)
{
	apol_query_set_flag(p, &a->flags, is_indirect, APOL_QUERY_SOURCE_INDIRECT);
	return apol_query_set(p, &a->source, NULL, symbol);
}

int apol_avrule_query_set_source_component(const apol_policy_t * p, apol_avrule_query_t * a, unsigned int component)
{
	if (!a || !(component & APOL_QUERY_SYMBOL_IS_BOTH)) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	apol_query_set_flag(p, &a->flags, component & APOL_QUERY_SYMBOL_IS_TYPE, APOL_QUERY_SOURCE_TYPE);
	apol_query_set_flag(p, &a->flags, component & APOL_QUERY_SYMBOL_IS_ATTRIBUTE, APOL_QUERY_SOURCE_ATTRIBUTE);
	return 0;
}

int apol_avrule_query_set_target(const apol_policy_t * p, apol_avrule_query_t * a, const char *symbol, int is_indirect)
{
	apol_query_set_flag(p, &a->flags, is_indirect, APOL_QUERY_TARGET_INDIRECT);
	return apol_query_set(p, &a->target, NULL, symbol);
}

int apol_avrule_query_set_target_component(const apol_policy_t * p, apol_avrule_query_t * a, unsigned int component)
{
	if (!a || !(component && APOL_QUERY_SYMBOL_IS_BOTH)) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	apol_query_set_flag(p, &a->flags, component & APOL_QUERY_SYMBOL_IS_TYPE, APOL_QUERY_TARGET_TYPE);
	apol_query_set_flag(p, &a->flags, component & APOL_QUERY_SYMBOL_IS_ATTRIBUTE, APOL_QUERY_TARGET_ATTRIBUTE);
	return 0;
}

int apol_avrule_query_append_class(const apol_policy_t * p, apol_avrule_query_t * a, const char *obj_class)
{
	char *s = NULL;
	if (obj_class == NULL) {
		apol_vector_destroy(&a->classes);
	} else if ((s = strdup(obj_class)) == NULL || (a->classes == NULL && (a->classes = apol_vector_create(free)) == NULL)
		   || apol_vector_append(a->classes, s) < 0) {
		ERR(p, "%s", strerror(errno));
		free(s);
		return -1;
	}
	return 0;
}

int apol_avrule_query_append_perm(const apol_policy_t * p, apol_avrule_query_t * a, const char *perm)
{
	char *s;
	if (perm == NULL) {
		apol_vector_destroy(&a->perms);
	} else if ((s = strdup(perm)) == NULL ||
		   (a->perms == NULL && (a->perms = apol_vector_create(free)) == NULL) || apol_vector_append(a->perms, s) < 0) {
		ERR(p, "%s", strerror(ENOMEM));
		return -1;
	}
	return 0;
}

int apol_avrule_query_set_bool(const apol_policy_t * p, apol_avrule_query_t * a, const char *bool_name)
{
	return apol_query_set(p, &a->bool_name, NULL, bool_name);
}

int apol_avrule_query_set_enabled(const apol_policy_t * p, apol_avrule_query_t * a, int is_enabled)
{
	return apol_query_set_flag(p, &a->flags, is_enabled, APOL_QUERY_ONLY_ENABLED);
}

int apol_avrule_query_set_all_perms(const apol_policy_t * p, apol_avrule_query_t * a, int match_all)
{
	return apol_query_set_flag(p, &a->flags, match_all, APOL_QUERY_MATCH_ALL_PERMS);
}

int apol_avrule_query_set_source_any(const apol_policy_t * p, apol_avrule_query_t * a, int is_any)
{
	return apol_query_set_flag(p, &a->flags, is_any, APOL_QUERY_SOURCE_AS_ANY);
}

int apol_avrule_query_set_regex(const apol_policy_t * p, apol_avrule_query_t * a, int is_regex)
{
	return apol_query_set_regex(p, &a->flags, is_regex);
}

/**
 * Comparison function for two syntactic avrules.  Will return -1 if
 * a's line number is before b's, 1 if b is greater.
 */
static int apol_syn_avrule_comp(const void *a, const void *b, void *data)
{
	qpol_syn_avrule_t *r1 = (qpol_syn_avrule_t *) a;
	qpol_syn_avrule_t *r2 = (qpol_syn_avrule_t *) b;
	apol_policy_t *p = (apol_policy_t *) data;
	unsigned long num1, num2;
	if (qpol_syn_avrule_get_lineno(p->p, r1, &num1) < 0 || qpol_syn_avrule_get_lineno(p->p, r2, &num2) < 0) {
		return 0;
	}
	if (num1 != num2) {
		return (int)num1 - (int)num2;
	}
	return (int)((char *)r1 - (char *)r2);
}

apol_vector_t *apol_avrule_to_syn_avrules(const apol_policy_t * p, const qpol_avrule_t * rule, const apol_vector_t * perms)
{
	apol_vector_t *v = NULL;
	qpol_iterator_t *iter = NULL, *perm_iter = NULL;
	qpol_syn_avrule_t *syn_avrule;
	char *perm;
	size_t i;
	int retval = -1, error = 0, found_perm = 0;
	if (qpol_avrule_get_syn_avrule_iter(p->p, rule, &iter) < 0) {
		error = errno;
		goto cleanup;
	}
	if ((v = apol_vector_create(NULL)) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&syn_avrule) < 0) {
			error = errno;
			ERR(p, "%s", strerror(error));
			goto cleanup;
		}
		found_perm = 0;
		if (perms != NULL && apol_vector_get_size(perms) > 0) {
			if (qpol_syn_avrule_get_perm_iter(p->p, syn_avrule, &perm_iter) < 0) {
				goto cleanup;
			}
			for (; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
				if (qpol_iterator_get_item(perm_iter, (void **)&perm) < 0) {
					error = errno;
					ERR(p, "%s", strerror(error));
					goto cleanup;
				}
				if (apol_vector_get_index(perms, perm, apol_str_strcmp, NULL, &i) == 0) {
					found_perm = 1;
					break;
				}
			}
		} else {
			found_perm = 1;
		}
		if (found_perm && apol_vector_append(v, syn_avrule) < 0) {
			error = errno;
			ERR(p, "%s", strerror(error));
			goto cleanup;
		}
	}
	/* explicit cast to void* since vector's arbitrary data is non-const */
	apol_vector_sort_uniquify(v, apol_syn_avrule_comp, (void *)p);
	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
	qpol_iterator_destroy(&perm_iter);
	if (retval != 0) {
		apol_vector_destroy(&v);
		errno = error;
		return NULL;
	}
	return v;
}

apol_vector_t *apol_avrule_list_to_syn_avrules(const apol_policy_t * p, const apol_vector_t * rules, const apol_vector_t * perms)
{
	apol_bst_t *b = NULL;
	qpol_avrule_t *rule;
	qpol_iterator_t *iter = NULL;
	qpol_syn_avrule_t *syn_avrule;
	char *perm;
	apol_vector_t *tmp_v = NULL, *v = NULL;
	size_t i, x;
	int retval = -1, error = 0, found_perm = 0;

	if ((b = apol_bst_create(apol_syn_avrule_comp, NULL)) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(rules); i++) {
		rule = apol_vector_get_element(rules, i);
		if (qpol_avrule_get_syn_avrule_iter(p->p, rule, &iter) < 0) {
			error = errno;
			goto cleanup;
		}
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&syn_avrule) < 0) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto cleanup;
			}
			/* explicit cast to void* since bst's arbitrary data is non-const */
			if (apol_bst_insert(b, syn_avrule, (void *)p) < 0) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto cleanup;
			}
		}
		qpol_iterator_destroy(&iter);
	}
	if ((tmp_v = apol_bst_get_vector(b, 1)) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto cleanup;
	}
	if (perms == NULL || apol_vector_get_size(perms) == 0) {
		v = tmp_v;
		tmp_v = NULL;
	} else {
		if ((v = apol_vector_create(NULL)) == NULL) {
			error = errno;
			ERR(p, "%s", strerror(error));
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(tmp_v); i++) {
			syn_avrule = apol_vector_get_element(tmp_v, i);
			found_perm = 0;
			if (qpol_syn_avrule_get_perm_iter(p->p, syn_avrule, &iter) < 0) {
				goto cleanup;
			}
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				if (qpol_iterator_get_item(iter, (void **)&perm) < 0) {
					error = errno;
					ERR(p, "%s", strerror(error));
					goto cleanup;
				}
				if (apol_vector_get_index(perms, perm, apol_str_strcmp, NULL, &x) == 0) {
					found_perm = 1;
					break;
				}
			}
			qpol_iterator_destroy(&iter);
			if (found_perm && apol_vector_append(v, syn_avrule) < 0) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto cleanup;
			}
		}
	}
	retval = 0;
      cleanup:
	apol_bst_destroy(&b);
	qpol_iterator_destroy(&iter);
	apol_vector_destroy(&tmp_v);
	if (retval != 0) {
		apol_vector_destroy(&v);
		errno = error;
		return NULL;
	}
	return v;
}

char *apol_avrule_render(const apol_policy_t * policy, const qpol_avrule_t * rule)
{
	char *tmp = NULL;
	const char *rule_type_str, *tmp_name = NULL;
	int error = 0;
	uint32_t rule_type = 0;
	const qpol_type_t *type = NULL;
	const qpol_class_t *obj_class = NULL;
	qpol_iterator_t *iter = NULL;
	size_t tmp_sz = 0, num_perms = 0;

	if (!policy || !rule) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}

	/* rule type */
	if (qpol_avrule_get_rule_type(policy->p, rule, &rule_type)) {
		return NULL;
	}
	if (!(rule_type &= (QPOL_RULE_ALLOW | QPOL_RULE_NEVERALLOW | QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT))) {
		ERR(policy, "%s", "Invalid AV rule type");
		errno = EINVAL;
		return NULL;
	}
	if (!(rule_type_str = apol_rule_type_to_str(rule_type))) {
		ERR(policy, "%s", "Could not get AV rule type's string");
		errno = EINVAL;
		return NULL;
	}
	if (apol_str_appendf(&tmp, &tmp_sz, "%s ", rule_type_str)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	/* source type */
	if (qpol_avrule_get_source_type(policy->p, rule, &type)) {
		error = errno;
		goto err;
	}
	if (qpol_type_get_name(policy->p, type, &tmp_name)) {
		error = errno;
		goto err;
	}
	if (apol_str_appendf(&tmp, &tmp_sz, "%s ", tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	/* target type */
	if (qpol_avrule_get_target_type(policy->p, rule, &type)) {
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
	if (qpol_avrule_get_object_class(policy->p, rule, &obj_class)) {
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

	/* perms */
	if (qpol_avrule_get_perm_iter(policy->p, rule, &iter)) {
		error = errno;
		goto err;
	}
	if (qpol_iterator_get_size(iter, &num_perms)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (num_perms > 1) {
		if (apol_str_append(&tmp, &tmp_sz, "{ ")) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		char *perm_name = NULL;
		if (qpol_iterator_get_item(iter, (void **)&perm_name)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
		if (apol_str_appendf(&tmp, &tmp_sz, "%s ", perm_name)) {
			error = errno;
			free(perm_name);
			ERR(policy, "%s", strerror(error));
			goto err;
		}
		free(perm_name);
		tmp_name = NULL;
	}
	if (num_perms > 1) {
		if (apol_str_append(&tmp, &tmp_sz, "} ")) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
	}

	if (apol_str_append(&tmp, &tmp_sz, ";")) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	qpol_iterator_destroy(&iter);
	return tmp;

      err:
	free(tmp);
	qpol_iterator_destroy(&iter);
	errno = error;
	return NULL;
}

char *apol_syn_avrule_render(const apol_policy_t * policy, const qpol_syn_avrule_t * rule)
{
	char *tmp = NULL;
	const char *rule_type_str, *tmp_name = NULL;
	int error = 0;
	uint32_t rule_type = 0, star = 0, comp = 0, self = 0;
	const qpol_type_t *type = NULL;
	const qpol_class_t *obj_class = NULL;
	qpol_iterator_t *iter = NULL, *iter2 = NULL;
	size_t tmp_sz = 0, iter_sz = 0, iter2_sz = 0;
	const qpol_type_set_t *set = NULL;

	if (!policy || !rule) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}

	/* rule type */
	if (qpol_syn_avrule_get_rule_type(policy->p, rule, &rule_type)) {
		return NULL;
	}
	if (!(rule_type &= (QPOL_RULE_ALLOW | QPOL_RULE_NEVERALLOW | QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT))) {
		ERR(policy, "%s", "Invalid AV rule type");
		errno = EINVAL;
		return NULL;
	}
	if (!(rule_type_str = apol_rule_type_to_str(rule_type))) {
		ERR(policy, "%s", "Could not get AV rule type's string");
		errno = EINVAL;
		return NULL;
	}
	if (apol_str_appendf(&tmp, &tmp_sz, "%s ", rule_type_str)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	/* source type set */
	if (qpol_syn_avrule_get_source_type_set(policy->p, rule, &set)) {
		error = errno;
		goto err;
	}
	if (qpol_type_set_get_is_star(policy->p, set, &star)) {
		error = errno;
		goto err;
	}
	if (star) {
		if (apol_str_append(&tmp, &tmp_sz, "* ")) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
	} else {
		if (qpol_type_set_get_is_comp(policy->p, set, &comp)) {
			error = errno;
			goto err;
		}
		if (comp) {
			if (apol_str_append(&tmp, &tmp_sz, "~")) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto err;
			}
		}
		if (qpol_type_set_get_included_types_iter(policy->p, set, &iter)) {
			error = errno;
			goto err;
		}
		if (qpol_type_set_get_subtracted_types_iter(policy->p, set, &iter2)) {
			error = errno;
			goto err;
		}
		if (qpol_iterator_get_size(iter, &iter_sz) || qpol_iterator_get_size(iter2, &iter2_sz)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
		if (iter_sz + iter2_sz > 1) {
			if (apol_str_append(&tmp, &tmp_sz, "{ ")) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto err;
			}
		}
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&type)) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto err;
			}
			if (qpol_type_get_name(policy->p, type, &tmp_name)) {
				error = errno;
				goto err;
			}
			if (apol_str_appendf(&tmp, &tmp_sz, "%s ", tmp_name)) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto err;
			}
		}
		for (; !qpol_iterator_end(iter2); qpol_iterator_next(iter2)) {
			if (qpol_iterator_get_item(iter2, (void **)&type)) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto err;
			}
			if (qpol_type_get_name(policy->p, type, &tmp_name)) {
				error = errno;
				goto err;
			}
			if (apol_str_appendf(&tmp, &tmp_sz, "-%s ", tmp_name)) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto err;
			}
		}
		qpol_iterator_destroy(&iter);
		qpol_iterator_destroy(&iter2);
		if (iter_sz + iter2_sz > 1) {
			if (apol_str_append(&tmp, &tmp_sz, "} ")) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto err;
			}
		}
	}

	/* target type set */
	if (qpol_syn_avrule_get_target_type_set(policy->p, rule, &set)) {
		error = errno;
		goto err;
	}
	if (qpol_type_set_get_is_star(policy->p, set, &star)) {
		error = errno;
		goto err;
	}
	if (star) {
		if (apol_str_append(&tmp, &tmp_sz, "* ")) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
	} else {
		if (qpol_type_set_get_is_comp(policy->p, set, &comp)) {
			error = errno;
			goto err;
		}
		if (comp) {
			if (apol_str_append(&tmp, &tmp_sz, "~")) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto err;
			}
		}
		if (qpol_type_set_get_included_types_iter(policy->p, set, &iter)) {
			error = errno;
			goto err;
		}
		if (qpol_type_set_get_subtracted_types_iter(policy->p, set, &iter2)) {
			error = errno;
			goto err;
		}
		if (qpol_iterator_get_size(iter, &iter_sz) || qpol_iterator_get_size(iter2, &iter2_sz)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
		if (qpol_syn_avrule_get_is_target_self(policy->p, rule, &self)) {
			error = errno;
			goto err;
		}
		if (iter_sz + iter2_sz + self > 1) {
			if (apol_str_append(&tmp, &tmp_sz, "{ ")) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto err;
			}
		}
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&type)) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto err;
			}
			if (qpol_type_get_name(policy->p, type, &tmp_name)) {
				error = errno;
				goto err;
			}
			if (apol_str_appendf(&tmp, &tmp_sz, "%s ", tmp_name)) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto err;
			}
		}
		for (; !qpol_iterator_end(iter2); qpol_iterator_next(iter2)) {
			if (qpol_iterator_get_item(iter2, (void **)&type)) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto err;
			}
			if (qpol_type_get_name(policy->p, type, &tmp_name)) {
				error = errno;
				goto err;
			}
			if (apol_str_appendf(&tmp, &tmp_sz, "-%s ", tmp_name)) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto err;
			}
		}
		qpol_iterator_destroy(&iter);
		qpol_iterator_destroy(&iter2);
		if (self) {
			if (apol_str_append(&tmp, &tmp_sz, "self ")) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto err;
			}
		}
		if (iter_sz + iter2_sz + self > 1) {
			if (apol_str_append(&tmp, &tmp_sz, "} ")) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto err;
			}
		}
	}

	if (apol_str_append(&tmp, &tmp_sz, ": ")) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	/* object classes */
	if (qpol_syn_avrule_get_class_iter(policy->p, rule, &iter)) {
		error = errno;
		goto err;
	}
	if (qpol_iterator_get_size(iter, &iter_sz)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (iter_sz > 1) {
		if (apol_str_append(&tmp, &tmp_sz, "{ ")) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&obj_class)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
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
	}
	qpol_iterator_destroy(&iter);
	if (iter_sz > 1) {
		if (apol_str_append(&tmp, &tmp_sz, "} ")) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
	}

	/* permissions */
	if (qpol_syn_avrule_get_perm_iter(policy->p, rule, &iter)) {
		error = errno;
		goto err;
	}
	if (qpol_iterator_get_size(iter, &iter_sz)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (iter_sz > 1) {
		if (apol_str_append(&tmp, &tmp_sz, "{ ")) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&tmp_name)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
		if (apol_str_appendf(&tmp, &tmp_sz, "%s ", tmp_name)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
	}
	qpol_iterator_destroy(&iter);
	if (iter_sz > 1) {
		if (apol_str_append(&tmp, &tmp_sz, "} ")) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
	}

	if (apol_str_append(&tmp, &tmp_sz, ";")) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	return tmp;

      err:
	free(tmp);
	qpol_iterator_destroy(&iter);
	qpol_iterator_destroy(&iter2);
	errno = error;
	return NULL;
}
