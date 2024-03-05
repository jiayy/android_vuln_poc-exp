/**
 * @file
 *
 * Provides a way for setools to make queries about type enforcement
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

struct apol_terule_query
{
	char *source, *target, *default_type, *bool_name;
	apol_vector_t *classes;
	unsigned int rules;
	unsigned int flags;
};

/**
 *  Common semantic rule selection routine used in get*rule_by_query.
 *  @param p Policy to search.
 *  @param v Vector of rules to populate (of type qpol_terule_t).
 *  @param rule_type Mask of rules to search.
 *  @param flags Query options as specified by the apol_terule_query.
 *  @param source_list If non-NULL, list of types to use as source.
 *  If NULL, accept all types.
 *  @param target_list If non-NULL, list of types to use as target.
 *  If NULL, accept all types.
 *  @param class_list If non-NULL, list of classes to use.
 *  If NULL, accept all classes.
 *  @param default_list If non-NULL, list of types to use as default.
 *  If NULL, accept all types.
 *  @param bool_name If non-NULL, find conditional rules affected by this boolean.
 *  If NULL, all rules will be considered (including unconditional rules).
 *  @return 0 on success and < 0 on failure.
 */
static int rule_select(const apol_policy_t * p, apol_vector_t * v, uint32_t rule_type, unsigned int flags,
		       const apol_vector_t * source_list, const apol_vector_t * target_list, const apol_vector_t * class_list,
		       const apol_vector_t * default_list, const char *bool_name)
{
	qpol_iterator_t *iter = NULL;
	int only_enabled = flags & APOL_QUERY_ONLY_ENABLED;
	int is_regex = flags & APOL_QUERY_REGEX;
	int source_as_any = flags & APOL_QUERY_SOURCE_AS_ANY;
	int retv = -1;
	regex_t *bool_regex = NULL;

	if (qpol_policy_get_terule_iter(p->p, rule_type, &iter) < 0) {
		goto cleanup;
	}

	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_terule_t *rule;
		uint32_t is_enabled;
		const qpol_cond_t *cond = NULL;
		int match_source = 0, match_target = 0, match_default = 0, match_bool = 0;
		size_t i;
		if (qpol_iterator_get_item(iter, (void **)&rule) < 0) {
			goto cleanup;
		}

		if (qpol_terule_get_is_enabled(p->p, rule, &is_enabled) < 0) {
			goto cleanup;
		}
		if (!is_enabled && only_enabled) {
			continue;
		}

		if (bool_name != NULL) {
			if (qpol_terule_get_cond(p->p, rule, &cond) < 0) {
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
			if (qpol_terule_get_source_type(p->p, rule, &source_type) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(source_list, source_type, NULL, NULL, &i) == 0) {
				match_source = 1;
			}
		}

		/* if source did not match, but treating source symbol
		 * as any field, then delay rejecting this rule until
		 * the target and default have been checked */
		if (!source_as_any && !match_source) {
			continue;
		}

		if (target_list == NULL || (source_as_any && match_source)) {
			match_target = 1;
		} else {
			const qpol_type_t *target_type;
			if (qpol_terule_get_target_type(p->p, rule, &target_type) < 0) {
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
			if (qpol_terule_get_default_type(p->p, rule, &default_type) < 0) {
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
			if (qpol_terule_get_object_class(p->p, rule, &obj_class) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(class_list, obj_class, NULL, NULL, &i) < 0) {
				continue;
			}
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
	return retv;
}

int apol_terule_get_by_query(const apol_policy_t * p, const apol_terule_query_t * t, apol_vector_t ** v)
{
	apol_vector_t *source_list = NULL, *target_list = NULL, *class_list = NULL, *default_list = NULL;
	int retval = -1, source_as_any = 0, is_regex = 0;
	char *bool_name = NULL;
	*v = NULL;
	unsigned int flags = 0;

	uint32_t rule_type = QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_MEMBER | QPOL_RULE_TYPE_CHANGE;
	if (t != NULL) {
		if (t->rules != 0) {
			rule_type &= t->rules;
		}
		flags = t->flags;
		is_regex = t->flags & APOL_QUERY_REGEX;
		bool_name = t->bool_name;
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

	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}

	if (rule_select(p, *v, rule_type, flags, source_list, target_list, class_list, default_list, bool_name)) {
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
		apol_vector_destroy(&default_list);
	}
	apol_vector_destroy(&class_list);
	return retval;
}

int apol_syn_terule_get_by_query(const apol_policy_t * p, const apol_terule_query_t * t, apol_vector_t ** v)
{
	apol_vector_t *source_list = NULL, *target_list = NULL, *class_list = NULL, *default_list = NULL, *syn_v = NULL;
	int retval = -1, source_as_any = 0, is_regex = 0;
	char *bool_name = NULL;
	*v = NULL;
	size_t i;
	unsigned int flags = 0;

	if (!p || !qpol_policy_has_capability(apol_policy_get_qpol(p), QPOL_CAP_SYN_RULES)) {
		ERR(p, "%s", strerror(EINVAL));
		goto cleanup;
	}

	uint32_t rule_type = QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_MEMBER | QPOL_RULE_TYPE_CHANGE;
	if (t != NULL) {
		if (t->rules != 0) {
			rule_type &= t->rules;
		}
		flags = t->flags;
		is_regex = t->flags & APOL_QUERY_REGEX;
		bool_name = t->bool_name;
		if (t->source != NULL &&
		    (source_list =
		     apol_query_create_candidate_syn_type_list(p, t->source, is_regex,
							       t->flags & APOL_QUERY_SOURCE_INDIRECT,
							       ((t->flags & (APOL_QUERY_SOURCE_TYPE |
									     APOL_QUERY_SOURCE_ATTRIBUTE)) /
								APOL_QUERY_SOURCE_TYPE))) == NULL) {
			goto cleanup;
		}
		if ((t->flags & APOL_QUERY_SOURCE_AS_ANY) && t->source != NULL) {
			default_list = target_list = source_list;
			source_as_any = 1;
		} else {
			if (t->target != NULL &&
			    (target_list =
			     apol_query_create_candidate_syn_type_list(p, t->target, is_regex,
								       t->flags & APOL_QUERY_TARGET_INDIRECT,
								       ((t->flags & (APOL_QUERY_TARGET_TYPE |
										     APOL_QUERY_TARGET_ATTRIBUTE))
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

	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}

	if (rule_select(p, *v, rule_type, flags, source_list, target_list, class_list, default_list, bool_name)) {
		goto cleanup;
	}

	syn_v = apol_terule_list_to_syn_terules(p, *v);
	if (!syn_v) {
		goto cleanup;
	}
	apol_vector_destroy(v);
	*v = syn_v;
	syn_v = NULL;

	/* if source and target are indirect skip post filtering type sets */
	if ((t->flags & APOL_QUERY_SOURCE_INDIRECT) && (t->flags & (APOL_QUERY_TARGET_INDIRECT | APOL_QUERY_SOURCE_AS_ANY))) {
		retval = 0;
		goto cleanup;
	}
	/* if not searching by source, target, or default we are done */
	if (!source_list && !target_list && !default_list) {
		retval = 0;
		goto cleanup;
	}

	if (source_list && !(t->flags & APOL_QUERY_SOURCE_INDIRECT)) {
		apol_vector_destroy(&source_list);
		source_list =
			apol_query_create_candidate_type_list(p, t->source, is_regex, 0,
							      ((t->flags & (APOL_QUERY_SOURCE_TYPE | APOL_QUERY_SOURCE_ATTRIBUTE)) /
							       APOL_QUERY_SOURCE_TYPE));
		if (!source_list)
			goto cleanup;
	}
	if (target_list && (source_as_any || !(t->flags & APOL_QUERY_TARGET_INDIRECT))) {
		if (source_as_any) {
			target_list = source_list;
		} else {
			apol_vector_destroy(&target_list);
			target_list =
				apol_query_create_candidate_type_list(p, t->target, is_regex, 0,
								      ((t->flags & (APOL_QUERY_SOURCE_TYPE |
										    APOL_QUERY_SOURCE_ATTRIBUTE)) /
								       APOL_QUERY_SOURCE_TYPE));
			if (!target_list)
				goto cleanup;
		}
	}
	if (source_as_any) {
		default_list = source_list;
	}

	for (i = 0; i < apol_vector_get_size(*v); i++) {
		qpol_syn_terule_t *srule = apol_vector_get_element(*v, i);
		const qpol_type_set_t *stypes = NULL, *ttypes = NULL;
		const qpol_type_t *dflt = NULL;
		size_t j;
		int uses_source = 0, uses_target = 0, uses_default = 0;
		qpol_syn_terule_get_source_type_set(p->p, srule, &stypes);
		qpol_syn_terule_get_target_type_set(p->p, srule, &ttypes);
		if (source_list && !(t->flags & APOL_QUERY_SOURCE_INDIRECT)) {
			uses_source = apol_query_type_set_uses_types_directly(p, stypes, source_list);
			if (uses_source < 0)
				goto cleanup;
		} else if (source_list && (t->flags & APOL_QUERY_SOURCE_INDIRECT)) {
			uses_source = 1;
		} else if (!source_list) {
			uses_source = 1;
		}

		if (target_list
		    && !(t->flags & APOL_QUERY_TARGET_INDIRECT || (source_as_any && t->flags & APOL_QUERY_SOURCE_INDIRECT))) {
			uses_target = apol_query_type_set_uses_types_directly(p, ttypes, target_list);
			if (uses_target < 0)
				goto cleanup;
		} else if (target_list
			   && (t->flags & APOL_QUERY_TARGET_INDIRECT || (source_as_any && t->flags & APOL_QUERY_SOURCE_INDIRECT))) {
			uses_target = 1;
		} else if (!target_list) {
			uses_target = 1;
		}

		if (default_list) {
			qpol_syn_terule_get_default_type(p->p, srule, &dflt);
			if (!apol_vector_get_index(default_list, (void *)dflt, NULL, NULL, &j))
				uses_default = 1;
		} else if (!default_list) {
			uses_default = 1;
		}

		if (!((uses_source && uses_target && uses_default)
		      || (source_as_any && (uses_source || uses_target || uses_default)))) {
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
	if (!source_as_any) {
		apol_vector_destroy(&target_list);
		apol_vector_destroy(&default_list);
	}
	apol_vector_destroy(&class_list);
	return retval;
}

apol_terule_query_t *apol_terule_query_create(void)
{
	apol_terule_query_t *t = calloc(1, sizeof(apol_terule_query_t));
	if (t != NULL) {
		t->rules = ~0U;
		t->flags =
			(APOL_QUERY_SOURCE_TYPE | APOL_QUERY_SOURCE_ATTRIBUTE | APOL_QUERY_TARGET_TYPE |
			 APOL_QUERY_TARGET_ATTRIBUTE);
	}
	return t;
}

void apol_terule_query_destroy(apol_terule_query_t ** t)
{
	if (*t != NULL) {
		free((*t)->source);
		free((*t)->target);
		free((*t)->default_type);
		free((*t)->bool_name);
		apol_vector_destroy(&(*t)->classes);
		free(*t);
		*t = NULL;
	}
}

int apol_terule_query_set_rules(const apol_policy_t * p __attribute__ ((unused)), apol_terule_query_t * t, unsigned int rules)
{
	if (rules != 0) {
		t->rules = rules;
	} else {
		t->rules = ~0U;
	}
	return 0;
}

int apol_terule_query_set_source(const apol_policy_t * p, apol_terule_query_t * t, const char *symbol, int is_indirect)
{
	apol_query_set_flag(p, &t->flags, is_indirect, APOL_QUERY_SOURCE_INDIRECT);
	return apol_query_set(p, &t->source, NULL, symbol);
}

int apol_terule_query_set_source_component(const apol_policy_t * p, apol_terule_query_t * t, unsigned int component)
{
	if (!t || !(component & APOL_QUERY_SYMBOL_IS_BOTH)) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	apol_query_set_flag(p, &t->flags, component & APOL_QUERY_SYMBOL_IS_TYPE, APOL_QUERY_SOURCE_TYPE);
	apol_query_set_flag(p, &t->flags, component & APOL_QUERY_SYMBOL_IS_ATTRIBUTE, APOL_QUERY_SOURCE_ATTRIBUTE);
	return 0;
}

int apol_terule_query_set_target(const apol_policy_t * p, apol_terule_query_t * t, const char *symbol, int is_indirect)
{
	apol_query_set_flag(p, &t->flags, is_indirect, APOL_QUERY_TARGET_INDIRECT);
	return apol_query_set(p, &t->target, NULL, symbol);
}

int apol_terule_query_set_target_component(const apol_policy_t * p, apol_terule_query_t * t, unsigned int component)
{
	if (!t || !(component & APOL_QUERY_SYMBOL_IS_BOTH)) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	apol_query_set_flag(p, &t->flags, component & APOL_QUERY_SYMBOL_IS_TYPE, APOL_QUERY_TARGET_TYPE);
	apol_query_set_flag(p, &t->flags, component & APOL_QUERY_SYMBOL_IS_ATTRIBUTE, APOL_QUERY_TARGET_ATTRIBUTE);
	return 0;
}

int apol_terule_query_set_default(const apol_policy_t * p, apol_terule_query_t * t, const char *symbol)
{
	return apol_query_set(p, &t->default_type, NULL, symbol);
}

int apol_terule_query_append_class(const apol_policy_t * p, apol_terule_query_t * t, const char *obj_class)
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

int apol_terule_query_set_bool(const apol_policy_t * p, apol_terule_query_t * t, const char *bool_name)
{
	return apol_query_set(p, &t->bool_name, NULL, bool_name);
}

int apol_terule_query_set_enabled(const apol_policy_t * p, apol_terule_query_t * t, int is_enabled)
{
	return apol_query_set_flag(p, &t->flags, is_enabled, APOL_QUERY_ONLY_ENABLED);
}

int apol_terule_query_set_source_any(const apol_policy_t * p, apol_terule_query_t * t, int is_any)
{
	return apol_query_set_flag(p, &t->flags, is_any, APOL_QUERY_SOURCE_AS_ANY);
}

int apol_terule_query_set_regex(const apol_policy_t * p, apol_terule_query_t * t, int is_regex)
{
	return apol_query_set_regex(p, &t->flags, is_regex);
}

/**
 * Comparison function for two syntactic terules.  Will return -1 if
 * a's line number is before b's, 1 if b is greater.
 */
static int apol_syn_terule_comp(const void *a, const void *b, void *data)
{
	qpol_syn_terule_t *r1 = (qpol_syn_terule_t *) a;
	qpol_syn_terule_t *r2 = (qpol_syn_terule_t *) b;
	apol_policy_t *p = (apol_policy_t *) data;
	unsigned long num1, num2;
	if (qpol_syn_terule_get_lineno(p->p, r1, &num1) < 0 || qpol_syn_terule_get_lineno(p->p, r2, &num2) < 0) {
		return 0;
	}
	if (num1 != num2) {
		return (int)num1 - (int)num2;
	}
	return (int)((char *)r1 - (char *)r2);
}

apol_vector_t *apol_terule_to_syn_terules(const apol_policy_t * p, const qpol_terule_t * rule)
{
	apol_vector_t *v = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_syn_terule_t *syn_terule;
	int retval = -1, error = 0;
	if (qpol_terule_get_syn_terule_iter(p->p, rule, &iter) < 0) {
		error = errno;
		goto cleanup;
	}
	if ((v = apol_vector_create(NULL)) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&syn_terule) < 0) {
			error = errno;
			ERR(p, "%s", strerror(error));
			goto cleanup;
		}
		if (apol_vector_append(v, syn_terule) < 0) {
			error = errno;
			ERR(p, "%s", strerror(error));
			goto cleanup;
		}
	}
	apol_vector_sort_uniquify(v, apol_syn_terule_comp, (void *)p);
	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
	if (retval != 0) {
		apol_vector_destroy(&v);
		errno = error;
		return NULL;
	}
	return v;
}

apol_vector_t *apol_terule_list_to_syn_terules(const apol_policy_t * p, const apol_vector_t * rules)
{
	apol_bst_t *b = NULL;
	qpol_terule_t *rule;
	qpol_iterator_t *iter = NULL;
	qpol_syn_terule_t *syn_terule;
	apol_vector_t *v = NULL;
	size_t i;
	int retval = -1, error = 0;

	if ((b = apol_bst_create(apol_syn_terule_comp, NULL)) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(rules); i++) {
		rule = apol_vector_get_element(rules, i);
		if (qpol_terule_get_syn_terule_iter(p->p, rule, &iter) < 0) {
			error = errno;
			goto cleanup;
		}
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&syn_terule) < 0) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto cleanup;
			}
			if (apol_bst_insert(b, syn_terule, (void *)p) < 0) {
				error = errno;
				ERR(p, "%s", strerror(error));
				goto cleanup;
			}
		}
		qpol_iterator_destroy(&iter);
	}
	if ((v = apol_bst_get_vector(b, 1)) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto cleanup;
	}
	retval = 0;
      cleanup:
	apol_bst_destroy(&b);
	qpol_iterator_destroy(&iter);
	if (retval != 0) {
		errno = error;
		return NULL;
	}
	return v;
}

char *apol_terule_render(const apol_policy_t * policy, const qpol_terule_t * rule)
{
	char *tmp = NULL;
	const char *tmp_name = NULL;
	const char *rule_type_str;
	int error = 0;
	size_t tmp_sz = 0;
	uint32_t rule_type = 0;
	const qpol_type_t *type = NULL;
	const qpol_class_t *obj_class = NULL;

	if (!policy || !rule) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}

	/* rule type */
	if (qpol_terule_get_rule_type(policy->p, rule, &rule_type)) {
		return NULL;
	}
	if (!(rule_type &= (QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER))) {
		ERR(policy, "%s", "Invalid TE rule type");
		errno = EINVAL;
		return NULL;
	}
	if (!(rule_type_str = apol_rule_type_to_str(rule_type))) {
		ERR(policy, "%s", "Could not get TE rule type's string");
		errno = EINVAL;
		return NULL;
	}
	if (apol_str_appendf(&tmp, &tmp_sz, "%s ", rule_type_str)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	/* source type */
	if (qpol_terule_get_source_type(policy->p, rule, &type)) {
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
	if (qpol_terule_get_target_type(policy->p, rule, &type)) {
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
	if (qpol_terule_get_object_class(policy->p, rule, &obj_class)) {
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
	if (qpol_terule_get_default_type(policy->p, rule, &type)) {
		error = errno;
		goto err;
	}
	if (qpol_type_get_name(policy->p, type, &tmp_name)) {
		error = errno;
		goto err;
	}
	if (apol_str_appendf(&tmp, &tmp_sz, "%s;", tmp_name)) {
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

char *apol_syn_terule_render(const apol_policy_t * policy, const qpol_syn_terule_t * rule)
{
	char *tmp = NULL;
	const char *tmp_name = NULL;
	const char *rule_type_str;
	int error = 0;
	uint32_t rule_type = 0, star = 0, comp = 0;
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
	if (qpol_syn_terule_get_rule_type(policy->p, rule, &rule_type)) {
		return NULL;
	}
	if (!(rule_type &= (QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER))) {
		ERR(policy, "%s", "Invalid TE rule type");
		errno = EINVAL;
		return NULL;
	}
	if (!(rule_type_str = apol_rule_type_to_str(rule_type))) {
		ERR(policy, "%s", "Could not get TE rule type's string");
		errno = EINVAL;
		return NULL;
	}
	if (apol_str_appendf(&tmp, &tmp_sz, "%s ", rule_type_str)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	/* source type set */
	if (qpol_syn_terule_get_source_type_set(policy->p, rule, &set)) {
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
		if (iter_sz + iter2_sz > 1) {
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
		if (iter_sz + iter2_sz > 1) {
			if (apol_str_append(&tmp, &tmp_sz, "} ")) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto err;
			}
		}
	}

	/* target type set */
	if (qpol_syn_terule_get_target_type_set(policy->p, rule, &set)) {
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
		if (iter_sz + iter2_sz > 1) {
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
		if (iter_sz + iter2_sz > 1) {
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
	if (qpol_syn_terule_get_class_iter(policy->p, rule, &iter)) {
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

	/* default type */
	if (qpol_syn_terule_get_default_type(policy->p, rule, &type)) {
		error = errno;
		goto err;
	}
	if (qpol_type_get_name(policy->p, type, &tmp_name)) {
		error = errno;
		goto err;
	}
	if (apol_str_appendf(&tmp, &tmp_sz, "%s;", tmp_name)) {
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
