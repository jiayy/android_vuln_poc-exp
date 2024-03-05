/**
 * @file
 * Implementation of the two-types relationship analysis.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
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
#include "domain-trans-analysis-internal.h"
#include "infoflow-analysis-internal.h"

#include <errno.h>
#include <string.h>

struct apol_types_relation_analysis
{
	char *typeA, *typeB;
	unsigned int analyses;
};

struct apol_types_relation_result
{
	/** vector of qpol_type_t pointers */
	apol_vector_t *attribs;
	/** vector of qpol_role_t pointers */
	apol_vector_t *roles;
	/** vector of qpol_user_t pointers */
	apol_vector_t *users;
	/** vector af apol_types_relation_access, rules that A has in common with B */
	apol_vector_t *simA;
	/** vector af apol_types_relation_access, rules that B has in common with A */
	apol_vector_t *simB;
	/** vector af apol_types_relation_access, types that A has that B does not */
	apol_vector_t *disA;
	/** vector af apol_types_relation_access, types that B has that A does not */
	apol_vector_t *disB;
	/** vector of qpol_avrule_t pointers */
	apol_vector_t *allows;
	/** vector of qpol_terule_t pointers */
	apol_vector_t *types;
	/** vector of apol_infoflow_result_t */
	apol_vector_t *dirflows;
	/** vector of apol_infoflow_result_t from type A to B */
	apol_vector_t *transAB;
	/** vector of apol_infoflow_result_t from type B to A */
	apol_vector_t *transBA;
	/** vector of apol_domain_trans_result_t from type A to B */
	apol_vector_t *domsAB;
	/** vector of apol_domain_trans_result_t from type B to A */
	apol_vector_t *domsBA;
};

struct apol_types_relation_access
{
	const qpol_type_t *type;
	/** vector of qpol_avrule_t pointers */
	apol_vector_t *rules;
};

/******************** actual analysis rountines ********************/

/**
 * Find the attributes that both typeA and typeB have.  Create a
 * vector of those attributes (as represented as qpol_type_t pointers
 * relative to the provided policy) and set r->attribs to that vector.
 *
 * @param p Policy containing types' information.
 * @param typeA First type to check.
 * @param typeB Other type to check.
 * @param r Result structure to fill.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_types_relation_common_attribs(const apol_policy_t * p,
					      const qpol_type_t * typeA, const qpol_type_t * typeB,
					      apol_types_relation_result_t * r)
{
	qpol_iterator_t *iA = NULL, *iB = NULL;
	apol_vector_t *vA = NULL, *vB = NULL;
	int retval = -1;

	if (qpol_type_get_attr_iter(p->p, typeA, &iA) < 0 || qpol_type_get_attr_iter(p->p, typeB, &iB) < 0) {
		goto cleanup;
	}
	if ((vA = apol_vector_create_from_iter(iA, NULL)) == NULL ||
	    (vB = apol_vector_create_from_iter(iB, NULL)) == NULL ||
	    (r->attribs = apol_vector_create_from_intersection(vA, vB, NULL, NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
	}

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iA);
	qpol_iterator_destroy(&iB);
	apol_vector_destroy(&vA);
	apol_vector_destroy(&vB);
	return retval;
}

/**
 * Find the roles whose allowed types include both typeA and typeB.
 * Create a vector of those roles (as represented as qpol_role_t
 * pointers relative to the provided policy) and set r->roles to that
 * vector.
 *
 * @param p Policy containing types' information.
 * @param typeA First type to check.
 * @param typeB Other type to check.
 * @param r Result structure to fill.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_types_relation_common_roles(const apol_policy_t * p,
					    const qpol_type_t * typeA, const qpol_type_t * typeB, apol_types_relation_result_t * r)
{
	const char *nameA, *nameB;
	apol_role_query_t *rq = NULL;
	apol_vector_t *vA = NULL, *vB = NULL;
	int retval = -1;

	if (qpol_type_get_name(p->p, typeA, &nameA) < 0 || qpol_type_get_name(p->p, typeB, &nameB) < 0) {
		goto cleanup;
	}
	if ((rq = apol_role_query_create()) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_role_query_set_type(p, rq, nameA) < 0 ||
	    apol_role_get_by_query(p, rq, &vA) < 0 ||
	    apol_role_query_set_type(p, rq, nameB) < 0 || apol_role_get_by_query(p, rq, &vB) < 0) {
		goto cleanup;
	}
	if ((r->roles = apol_vector_create_from_intersection(vA, vB, NULL, NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
	}

	retval = 0;
      cleanup:
	apol_role_query_destroy(&rq);
	apol_vector_destroy(&vA);
	apol_vector_destroy(&vB);
	return retval;
}

/**
 * Find the users whose roles have as their allowed types both typeA
 * and typeB.  Create a vector of those users (as represented as
 * qpol_user_t pointers relative to the provided policy) and set
 * r->users to that vector.
 *
 * @param p Policy containing types' information.
 * @param typeA First type to check.
 * @param typeB Other type to check.
 * @param r Result structure to fill.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_types_relation_common_users(const apol_policy_t * p,
					    const qpol_type_t * typeA, const qpol_type_t * typeB, apol_types_relation_result_t * r)
{
	const char *nameA, *nameB;
	apol_role_query_t *rq = NULL;
	apol_vector_t *vA = NULL, *vB = NULL;
	qpol_iterator_t *iter = NULL, *riter = NULL;
	int retval = -1;

	if (qpol_type_get_name(p->p, typeA, &nameA) < 0 || qpol_type_get_name(p->p, typeB, &nameB) < 0) {
		goto cleanup;
	}
	if ((rq = apol_role_query_create()) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_role_query_set_type(p, rq, nameA) < 0 ||
	    apol_role_get_by_query(p, rq, &vA) < 0 ||
	    apol_role_query_set_type(p, rq, nameB) < 0 || apol_role_get_by_query(p, rq, &vB) < 0) {
		goto cleanup;
	}

	if ((r->users = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	if (qpol_policy_get_user_iter(p->p, &iter) < 0) {
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_user_t *user;
		size_t i;
		int inA = 0, inB = 0;
		if (qpol_iterator_get_item(iter, (void **)&user) < 0) {
			goto cleanup;
		}
		if (qpol_user_get_role_iter(p->p, user, &riter) < 0) {
			goto cleanup;
		}
		for (; (!inA || !inB) && !qpol_iterator_end(riter); qpol_iterator_next(riter)) {
			qpol_role_t *role;
			if (qpol_iterator_get_item(riter, (void **)&role) < 0) {
				goto cleanup;
			}
			if (!inA && apol_vector_get_index(vA, role, NULL, NULL, &i) == 0) {
				inA = 1;
			}
			if (!inB && apol_vector_get_index(vB, role, NULL, NULL, &i) == 0) {
				inB = 1;
			}
		}
		qpol_iterator_destroy(&riter);
		if (inA && inB && apol_vector_append(r->users, user) < 0) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	apol_role_query_destroy(&rq);
	apol_vector_destroy(&vA);
	apol_vector_destroy(&vB);
	qpol_iterator_destroy(&iter);
	qpol_iterator_destroy(&riter);
	return retval;
}

/**
 * Comparison function for a vector of apol_types_relation_access_t
 * pointers.  Returns 0 if the access type at a matches the type b.
 *
 * @param a Pointer to an existing apol_types_relation_access_t.
 * @param b Pointer to a qpol_type_t.
 * @param data Unused.
 *
 * @return 0 if a's type matchs b, non-zero if not.
 */
static int apol_types_relation_access_compfunc(const void *a, const void *b, void *data __attribute__ ((unused)))
{
	apol_types_relation_access_t *access = (apol_types_relation_access_t *) a;
	qpol_type_t *t = (qpol_type_t *) b;
	return (int)((char *)access->type - (char *)t);
}

/**
 * Comparison function for a vector of apol_types_relation_access_t
 * pointers.  Returns 0 if the access type a matches the access type b.
 *
 * @param a Pointer to an existing apol_types_relation_access_t.
 * @param b Pointer to another existing apol_types_relation_access_t.
 * @param data Unused.
 *
 * @return 0 if a's type matchs b, non-zero if not.
 */
static int apol_types_relation_access_compfunc2(const void *a, const void *b, void *data __attribute__ ((unused)))
{
	apol_types_relation_access_t *accessA = (apol_types_relation_access_t *) a;
	apol_types_relation_access_t *accessB = (apol_types_relation_access_t *) b;
	return (int)((char *)accessA->type - (char *)accessB->type);
}

/**
 * Deallocate all space associated with a types relation access node,
 * including the pointer itself.  Does nothing if the pointer is
 * alread NULL.
 *
 * @param data Pointer to an access node to free.
 */
static void apol_types_relation_access_free(void *data)
{
	apol_types_relation_access_t *a = (apol_types_relation_access_t *) data;
	if (a != NULL) {
		apol_vector_destroy(&a->rules);
		free(a);
	}
}

/**
 * Adds a rule to a vector of apol_types_relation_access_t pointers.
 * Expands the rule's target type, appending new entries as necessary.
 *
 * @param p Policy from which rule originated.
 * @param r Rule to expand and append.
 * @param access Vector of apol_types_relation_access_t.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_types_relation_access_append_rule(const apol_policy_t * p, const qpol_avrule_t * r, apol_vector_t * access)
{
	const qpol_type_t *t;
	apol_vector_t *expanded = NULL;
	size_t i, j;
	apol_types_relation_access_t *a;
	int retval = -1;
	if (qpol_avrule_get_target_type(p->p, r, &t) < 0 || (expanded = apol_query_expand_type(p, t)) == NULL) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(expanded); i++) {
		t = apol_vector_get_element(expanded, i);
		if (apol_vector_get_index(access, t, apol_types_relation_access_compfunc, NULL, &j) == 0) {
			a = (apol_types_relation_access_t *) apol_vector_get_element(access, j);
		} else {
			if ((a = calloc(1, sizeof(*a))) == NULL ||
			    (a->rules = apol_vector_create(NULL)) == NULL || apol_vector_append(access, a) < 0) {
				ERR(p, "%s", strerror(errno));
				apol_types_relation_access_free(a);
				goto cleanup;
			}
			a->type = t;
		}
		if (apol_vector_append(a->rules, (void *)r) < 0) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&expanded);
	return retval;
}

/**
 * The following builds separate databases to hold rules for typeA and
 * typeB respectively.  The database holds a vector of pointers to
 * apol_types_relation_access_t objects.  Then compare access lists
 * for typeA and typeB, determine common and unique access and have
 * easy access to the relevant rules.
 *
 * @param p Policy to look up av rules.
 * @param typeA First type to build access list.
 * @param typeB Other type to build access list.
 * @param accessesA Vector of apol_types_relation_access_t for typeA.
 * @param accessesB Vector of apol_types_relation_access_t for typeB.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_types_relation_create_access_pools(const apol_policy_t * p,
						   const qpol_type_t * typeA,
						   const qpol_type_t * typeB, apol_vector_t * accessesA, apol_vector_t * accessesB)
{
	const char *nameA, *nameB;
	apol_avrule_query_t *aq = NULL;
	apol_vector_t *vA = NULL, *vB = NULL;
	size_t i;
	int retval = -1;

	if (qpol_type_get_name(p->p, typeA, &nameA) < 0 || qpol_type_get_name(p->p, typeB, &nameB) < 0) {
		goto cleanup;
	}
	if ((aq = apol_avrule_query_create()) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_avrule_query_set_rules(p, aq, QPOL_RULE_ALLOW) < 0 ||
	    apol_avrule_query_set_source(p, aq, nameA, 1) < 0 ||
	    apol_avrule_get_by_query(p, aq, &vA) < 0 ||
	    apol_avrule_query_set_source(p, aq, nameB, 1) < 0 || apol_avrule_get_by_query(p, aq, &vB) < 0) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(vA); i++) {
		qpol_avrule_t *r = (qpol_avrule_t *) apol_vector_get_element(vA, i);
		if (apol_types_relation_access_append_rule(p, r, accessesA) < 0) {
			goto cleanup;
		}
	}
	for (i = 0; i < apol_vector_get_size(vB); i++) {
		qpol_avrule_t *r = (qpol_avrule_t *) apol_vector_get_element(vB, i);
		if (apol_types_relation_access_append_rule(p, r, accessesB) < 0) {
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	apol_avrule_query_destroy(&aq);
	apol_vector_destroy(&vA);
	apol_vector_destroy(&vB);
	return retval;
}

/**
 * Allocate a new apol_types_relation_access_t and append it to a
 * vector.  The new access node's type will be set to a's type.  The
 * rules will be a clone of a's rules.
 *
 * @param p Policy from which rule originated.
 * @param a Access node to duplicate.
 * @param access Vector of apol_types_relation_access_t to append.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_types_relation_access_append(const apol_policy_t * p, const apol_types_relation_access_t * a,
					     apol_vector_t * access)
{
	apol_types_relation_access_t *new_a;
	int retval = -1;
	if ((new_a = calloc(1, sizeof(*new_a))) == NULL
	    || (new_a->rules = apol_vector_create_from_vector(a->rules, NULL, NULL, NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	new_a->type = a->type;
	if (apol_vector_append(access, new_a) < 0) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	retval = 0;
      cleanup:
	if (retval != 0) {
		apol_types_relation_access_free(new_a);
	}
	return retval;
}

/**
 * Find accesses, both similar and dissimilar, between both typeA and
 * typeB.
 *
 * @param p Policy containing types' information.
 * @param typeA First type to check.
 * @param typeB Other type to check.
 * @param do_similar 1 if to calculate similar accesses, 0 to skip.
 * @param do_dissimilar 1 if to calculate dissimilar accesses, 0 to skip.
 * @param r Result structure to fill.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_types_relation_accesses(const apol_policy_t * p,
					const qpol_type_t * typeA,
					const qpol_type_t * typeB, int do_similar, int do_dissimilar,
					apol_types_relation_result_t * r)
{
	apol_vector_t *accessesA = NULL, *accessesB = NULL;
	apol_types_relation_access_t *a, *b;
	size_t i, j;
	int retval = -1;

	if ((accessesA = apol_vector_create(apol_types_relation_access_free)) == NULL
	    || (accessesB = apol_vector_create(apol_types_relation_access_free)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	if (apol_types_relation_create_access_pools(p, typeA, typeB, accessesA, accessesB) < 0) {
		goto cleanup;
	}
	apol_vector_sort(accessesA, apol_types_relation_access_compfunc2, NULL);
	apol_vector_sort(accessesB, apol_types_relation_access_compfunc2, NULL);

	if (do_similar) {
		if ((r->simA = apol_vector_create(apol_types_relation_access_free)) == NULL
		    || (r->simB = apol_vector_create(apol_types_relation_access_free)) == NULL) {
			ERR(p, "%s", strerror(errno));
			goto cleanup;
		}
	}
	if (do_dissimilar) {
		if ((r->disA = apol_vector_create(apol_types_relation_access_free)) == NULL
		    || (r->disB = apol_vector_create(apol_types_relation_access_free)) == NULL) {
			ERR(p, "%s", strerror(errno));
			goto cleanup;
		}
	}

	/* Step through each element for each access sorted list.  If
	 * their types match and if do_similiar, then append the union
	 * of the access rules to the results.  If their types do not
	 * match and if do_similar then add to results.
	 */
	for (i = j = 0; i < apol_vector_get_size(accessesA) && j < apol_vector_get_size(accessesB);) {
		a = (apol_types_relation_access_t *) apol_vector_get_element(accessesA, i);
		b = (apol_types_relation_access_t *) apol_vector_get_element(accessesB, j);
		if (a->type == b->type) {
			if (do_similar &&
			    (apol_types_relation_access_append(p, a, r->simA) < 0 ||
			     apol_types_relation_access_append(p, b, r->simB) < 0)) {
				goto cleanup;
			}
			i++;
			j++;
		} else {
			if (a->type < b->type) {
				if (do_dissimilar && apol_types_relation_access_append(p, a, r->disA) < 0) {
					goto cleanup;
				}
				i++;
			} else {
				if (do_dissimilar && apol_types_relation_access_append(p, b, r->disB) < 0) {
					goto cleanup;
				}
				j++;
			}
		}
	}
	for (; do_dissimilar && i < apol_vector_get_size(accessesA); i++) {
		a = (apol_types_relation_access_t *) apol_vector_get_element(accessesA, i);
		if (apol_types_relation_access_append(p, a, r->disA) < 0) {
			goto cleanup;
		}
	}
	for (; do_dissimilar && j < apol_vector_get_size(accessesB); j++) {
		b = (apol_types_relation_access_t *) apol_vector_get_element(accessesB, j);
		if (apol_types_relation_access_append(p, b, r->disB) < 0) {
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	apol_vector_destroy(&accessesA);
	apol_vector_destroy(&accessesB);
	return retval;
}

/**
 * Find all allow rules that involve both types.  Create a vector of
 * those rules (as represented as qpol_avrule_t pointers relative to
 * the provided policy) and set r->allows to that vector.
 *
 * @param p Policy containing types' information.
 * @param typeA First type to check.
 * @param typeB Other type to check.
 * @param r Result structure to fill.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_types_relation_allows(const apol_policy_t * p, const qpol_type_t * typeA, const qpol_type_t * typeB,
				      apol_types_relation_result_t * r)
{
	const char *nameA, *nameB;
	apol_avrule_query_t *aq = NULL;
	apol_vector_t *v = NULL;
	int retval = -1;

	if (qpol_type_get_name(p->p, typeA, &nameA) < 0 || qpol_type_get_name(p->p, typeB, &nameB) < 0) {
		goto cleanup;
	}
	if ((aq = apol_avrule_query_create()) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_avrule_query_set_rules(p, aq, QPOL_RULE_ALLOW) < 0 ||
	    apol_avrule_query_set_source(p, aq, nameA, 1) < 0 ||
	    apol_avrule_query_set_target(p, aq, nameB, 1) < 0 || apol_avrule_get_by_query(p, aq, &r->allows) < 0) {
		goto cleanup;
	}
	if (apol_avrule_query_set_source(p, aq, nameB, 1) < 0 ||
	    apol_avrule_query_set_target(p, aq, nameA, 1) < 0 || apol_avrule_get_by_query(p, aq, &v) < 0) {
		goto cleanup;
	}
	if (apol_vector_cat(r->allows, v) < 0) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	retval = 0;
      cleanup:
	apol_avrule_query_destroy(&aq);
	apol_vector_destroy(&v);
	return retval;
}

/**
 * Find all type transition / type change rules that involve both
 * types.  Create a vector of those rules (as represented as
 * qpol_terule_t pointers relative to the provided policy) and set
 * r->types to that vector.
 *
 * @param p Policy containing types' information.
 * @param typeA First type to check.
 * @param typeB Other type to check.
 * @param r Result structure to fill.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_types_relation_types(const apol_policy_t * p, const qpol_type_t * typeA, const qpol_type_t * typeB,
				     apol_types_relation_result_t * r)
{
	const char *nameA, *nameB;
	apol_terule_query_t *tq = NULL;
	apol_vector_t *v = NULL, *candidate_types = NULL;
	const qpol_terule_t *rule;
	const qpol_type_t *target, *default_type;
	size_t i, j;
	int retval = -1;

	if (qpol_type_get_name(p->p, typeA, &nameA) < 0 || qpol_type_get_name(p->p, typeB, &nameB) < 0) {
		goto cleanup;
	}
	if ((r->types = apol_vector_create(NULL)) == NULL || (tq = apol_terule_query_create()) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_terule_query_set_rules(p, tq, QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE) < 0 ||
	    apol_terule_query_set_source(p, tq, nameA, 1) < 0 ||
	    apol_terule_get_by_query(p, tq, &v) < 0 ||
	    (candidate_types = apol_query_create_candidate_type_list(p, nameB, 0, 1, APOL_QUERY_SYMBOL_IS_BOTH)) == NULL) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		rule = (qpol_terule_t *) apol_vector_get_element(v, i);
		if (qpol_terule_get_target_type(p->p, rule, &target) < 0 ||
		    qpol_terule_get_default_type(p->p, rule, &default_type) < 0) {
			goto cleanup;
		}
		if ((apol_vector_get_index(candidate_types, target, NULL, NULL, &j) == 0 ||
		     apol_vector_get_index(candidate_types, default_type, NULL, NULL, &j) == 0) &&
		    apol_vector_append(r->types, (void *)rule) < 0) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}

	apol_vector_destroy(&v);
	apol_vector_destroy(&candidate_types);
	if (apol_terule_query_set_source(p, tq, nameB, 1) < 0 ||
	    apol_terule_get_by_query(p, tq, &v) < 0 ||
	    (candidate_types = apol_query_create_candidate_type_list(p, nameA, 0, 1, APOL_QUERY_SYMBOL_IS_BOTH)) == NULL) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		rule = (qpol_terule_t *) apol_vector_get_element(v, i);
		if (qpol_terule_get_target_type(p->p, rule, &target) < 0 ||
		    qpol_terule_get_default_type(p->p, rule, &default_type) < 0) {
			goto cleanup;
		}
		if ((apol_vector_get_index(candidate_types, target, NULL, NULL, &j) == 0 ||
		     apol_vector_get_index(candidate_types, default_type, NULL, NULL, &j) == 0) &&
		    apol_vector_append(r->types, (void *)rule) < 0) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	apol_terule_query_destroy(&tq);
	apol_vector_destroy(&v);
	apol_vector_destroy(&candidate_types);
	return retval;
}

/**
 * Given a vector of apol_infoflow_result_t objects, deep copy to the
 * results vector those infoflow results whose target type matches
 * target_name (or any of target_name's attributes or aliases).
 *
 * @param p Policy within which to lookup types.
 * @param v Vector of existing apol_infoflow_result_t.
 * @param target_name Target type name.
 * @param results Vector to which clone matching infoflow results.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_types_relation_clone_infoflow(const apol_policy_t * p, const apol_vector_t * v, const char *target_name,
					      apol_vector_t * results)
{
	apol_vector_t *candidate_types = NULL;
	const qpol_type_t *target;
	apol_infoflow_result_t *res, *new_res;
	size_t i, j;
	int retval = -1;
	if ((candidate_types = apol_query_create_candidate_type_list(p, target_name, 0, 1, APOL_QUERY_SYMBOL_IS_BOTH)) == NULL) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		res = (apol_infoflow_result_t *) apol_vector_get_element(v, i);
		target = apol_infoflow_result_get_end_type(res);
		if (apol_vector_get_index(candidate_types, target, NULL, NULL, &j) == 0) {
			if ((new_res = infoflow_result_create_from_infoflow_result(res)) == NULL ||
			    apol_vector_append(results, new_res) < 0) {
				infoflow_result_free(new_res);
				ERR(p, "%s", strerror(ENOMEM));
				goto cleanup;
			}
		}
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&candidate_types);
	return retval;
}

/**
 * Find all direct information flows between the two types.  Create a
 * vector of apol_infoflow_result_t and set r->dirflows to that vector.
 *
 * @param p Policy containing types' information.
 * @param typeA First type to check.
 * @param typeB Other type to check.
 * @param r Result structure to fill.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_types_relation_directflow(const apol_policy_t * p,
					  const qpol_type_t * typeA, const qpol_type_t * typeB, apol_types_relation_result_t * r)
{
	const char *nameA, *nameB;
	apol_infoflow_analysis_t *ia = NULL;
	apol_vector_t *v = NULL;
	apol_infoflow_graph_t *g = NULL;
	int retval = -1;

	if (qpol_type_get_name(p->p, typeA, &nameA) < 0 || qpol_type_get_name(p->p, typeB, &nameB) < 0) {
		goto cleanup;
	}
	if ((r->dirflows = apol_vector_create(infoflow_result_free)) == NULL || (ia = apol_infoflow_analysis_create()) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_infoflow_analysis_set_mode(p, ia, APOL_INFOFLOW_MODE_DIRECT) < 0 ||
	    apol_infoflow_analysis_set_dir(p, ia, APOL_INFOFLOW_EITHER) < 0 ||
	    apol_infoflow_analysis_set_type(p, ia, nameA) < 0 || apol_infoflow_analysis_do(p, ia, &v, &g) < 0) {
		goto cleanup;
	}
	if (apol_types_relation_clone_infoflow(p, v, nameB, r->dirflows) < 0) {
		goto cleanup;
	}

	retval = 0;
      cleanup:
	apol_vector_destroy(&v);
	apol_infoflow_analysis_destroy(&ia);
	apol_infoflow_graph_destroy(&g);
	return retval;
}

/**
 * Find (some) transitive information flows between the two types.
 *
 * @param p Policy containing types' information.
 * @param typeA First type to check.
 * @param typeB Other type to check.
 * @param do_transAB 1 if to find paths from type A to B, 0 to skip.
 * @param do_transBA 1 if to find paths from type B to A, 0 to skip.
 * @param r Result structure to fill.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_types_relation_transflow(const apol_policy_t * p,
					 const qpol_type_t * typeA,
					 const qpol_type_t * typeB,
					 unsigned int do_transAB, unsigned int do_transBA, apol_types_relation_result_t * r)
{
	const char *nameA, *nameB;
	apol_infoflow_analysis_t *ia = NULL;
	apol_vector_t *v = NULL;
	apol_infoflow_graph_t *g = NULL;
	int retval = -1;

	if (qpol_type_get_name(p->p, typeA, &nameA) < 0 || qpol_type_get_name(p->p, typeB, &nameB) < 0) {
		goto cleanup;
	}
	if ((ia = apol_infoflow_analysis_create()) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_infoflow_analysis_set_mode(p, ia, APOL_INFOFLOW_MODE_TRANS) < 0 ||
	    apol_infoflow_analysis_set_dir(p, ia, APOL_INFOFLOW_OUT) < 0) {
		goto cleanup;
	}
	if (do_transAB) {
		if (apol_infoflow_analysis_set_type(p, ia, nameA) < 0 || apol_infoflow_analysis_do(p, ia, &v, &g) < 0) {
			goto cleanup;
		}
		if ((r->transAB = apol_vector_create(infoflow_result_free)) == NULL) {
			ERR(p, "%s", strerror(errno));
			goto cleanup;
		}
		if (apol_types_relation_clone_infoflow(p, v, nameB, r->transAB) < 0) {
			goto cleanup;
		}
	}
	if (do_transBA) {
		apol_vector_destroy(&v);
		if ((do_transAB &&
		     apol_infoflow_analysis_do_more(p, g, nameB, &v) < 0) ||
		    (!do_transAB &&
		     (apol_infoflow_analysis_set_type(p, ia, nameB) < 0 || apol_infoflow_analysis_do(p, ia, &v, &g) < 0))) {
			goto cleanup;
		}
		if ((r->transBA = apol_vector_create(infoflow_result_free)) == NULL) {
			ERR(p, "%s", strerror(errno));
			goto cleanup;
		}
		if (apol_types_relation_clone_infoflow(p, v, nameA, r->transBA) < 0) {
			goto cleanup;
		}
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&v);
	apol_infoflow_analysis_destroy(&ia);
	apol_infoflow_graph_destroy(&g);
	return retval;
}

/**
 * Given a vector of apol_domain_trans_result_t objects, deep copy to
 * the results vector those domain transition results whose target
 * type matches target_name (or any of target_name's attributes or
 * aliases).
 *
 * @param p Policy within which to lookup types.
 * @param v Vector of existing apol_domain_trans_result_t.
 * @param target_name Target type name.
 * @param results Vector to which clone matching domain transition
 * results.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_types_relation_clone_domaintrans(const apol_policy_t * p, const apol_vector_t * v, const char *target_name,
						 apol_vector_t * results)
{
	apol_vector_t *candidate_types = NULL;
	const qpol_type_t *target;
	apol_domain_trans_result_t *res, *new_res;
	size_t i, j;
	int retval = -1;
	if ((candidate_types = apol_query_create_candidate_type_list(p, target_name, 0, 1, APOL_QUERY_SYMBOL_IS_BOTH)) == NULL) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(v); i++) {
		res = (apol_domain_trans_result_t *) apol_vector_get_element(v, i);
		target = apol_domain_trans_result_get_end_type(res);
		if (apol_vector_get_index(candidate_types, target, NULL, NULL, &j) == 0) {
			if ((new_res = apol_domain_trans_result_create_from_domain_trans_result(res)) == NULL ||
			    apol_vector_append(results, new_res) < 0) {
				domain_trans_result_free(new_res);
				ERR(p, "%s", strerror(ENOMEM));
				goto cleanup;
			}
		}
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&candidate_types);
	return retval;
}

/**
 * Find domain transitions between the two types.
 *
 * @param p Policy containing types' information.
 * @param typeA First type to check.
 * @param typeB Other type to check.
 * @param do_domainAB 1 if to find transitions from type A to B, 0 to skip.
 * @param do_domainBA 1 if to find transitions from type B to A, 0 to skip.
 * @param r Result structure to fill.
 *
 * @return 0 on success, < 0 on error.
 */
static int apol_types_relation_domain(apol_policy_t * p,
				      const qpol_type_t * typeA,
				      const qpol_type_t * typeB,
				      unsigned int do_domainsAB, unsigned int do_domainsBA, apol_types_relation_result_t * r)
{
	const char *nameA, *nameB;
	apol_domain_trans_analysis_t *dta = NULL;
	apol_vector_t *v = NULL;
	int retval = -1;

	if (qpol_type_get_name(p->p, typeA, &nameA) < 0 || qpol_type_get_name(p->p, typeB, &nameB) < 0) {
		goto cleanup;
	}
	if ((dta = apol_domain_trans_analysis_create()) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if (apol_policy_build_domain_trans_table(p) < 0 ||
	    apol_domain_trans_analysis_set_direction(p, dta, APOL_DOMAIN_TRANS_DIRECTION_FORWARD) < 0) {
		goto cleanup;
	}
	if (do_domainsAB) {
		apol_policy_reset_domain_trans_table(p);
		if (apol_domain_trans_analysis_set_start_type(p, dta, nameA) < 0 || apol_domain_trans_analysis_do(p, dta, &v) < 0) {
			goto cleanup;
		}
		if ((r->domsAB = apol_vector_create(domain_trans_result_free)) == NULL) {
			ERR(p, "%s", strerror(errno));
			goto cleanup;
		}
		if (apol_types_relation_clone_domaintrans(p, v, nameB, r->domsAB) < 0) {
			goto cleanup;
		}
	}
	if (do_domainsBA) {
		apol_vector_destroy(&v);
		apol_policy_reset_domain_trans_table(p);
		if (apol_domain_trans_analysis_set_start_type(p, dta, nameB) < 0 || apol_domain_trans_analysis_do(p, dta, &v) < 0) {
			goto cleanup;
		}
		if ((r->domsBA = apol_vector_create(domain_trans_result_free)) == NULL) {
			ERR(p, "%s", strerror(errno));
			goto cleanup;
		}
		if (apol_types_relation_clone_domaintrans(p, v, nameA, r->domsBA) < 0) {
			goto cleanup;
		}
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&v);
	apol_domain_trans_analysis_destroy(&dta);
	return retval;
}

/******************** public functions below ********************/

int apol_types_relation_analysis_do(apol_policy_t * p, const apol_types_relation_analysis_t * tr, apol_types_relation_result_t ** r)
{
	const qpol_type_t *typeA, *typeB;
	unsigned char isattrA, isattrB;
	unsigned int do_similar_access, do_dissimilar_access;
	unsigned int do_transAB, do_transBA;
	unsigned int do_domainAB, do_domainBA;
	int retval = -1;
	*r = NULL;

	if (tr->typeA == NULL || tr->typeB == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		goto cleanup;
	}
	if (apol_query_get_type(p, tr->typeA, &typeA) < 0 ||
	    apol_query_get_type(p, tr->typeB, &typeB) < 0 ||
	    qpol_type_get_isattr(p->p, typeA, &isattrA) < 0 || qpol_type_get_isattr(p->p, typeB, &isattrB) < 0) {
		goto cleanup;
	}
	if (isattrA) {
		ERR(p, "Symbol %s is an attribute.", tr->typeA);
		goto cleanup;
	}
	if (isattrB) {
		ERR(p, "Symbol %s is an attribute.", tr->typeB);
		goto cleanup;
	}
	if ((*r = calloc(1, sizeof(**r))) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if ((tr->analyses & APOL_TYPES_RELATION_COMMON_ATTRIBS) && apol_types_relation_common_attribs(p, typeA, typeB, *r) < 0) {
		goto cleanup;
	}
	if ((tr->analyses & APOL_TYPES_RELATION_COMMON_ROLES) && apol_types_relation_common_roles(p, typeA, typeB, *r) < 0) {
		goto cleanup;
	}
	if ((tr->analyses & APOL_TYPES_RELATION_COMMON_USERS) && apol_types_relation_common_users(p, typeA, typeB, *r) < 0) {
		goto cleanup;
	}
	do_similar_access = tr->analyses & APOL_TYPES_RELATION_SIMILAR_ACCESS;
	do_dissimilar_access = tr->analyses & APOL_TYPES_RELATION_DISSIMILAR_ACCESS;
	if ((do_similar_access || do_dissimilar_access) &&
	    apol_types_relation_accesses(p, typeA, typeB, do_similar_access, do_dissimilar_access, *r) < 0) {
		goto cleanup;
	}
	if ((tr->analyses & APOL_TYPES_RELATION_ALLOW_RULES) && apol_types_relation_allows(p, typeA, typeB, *r) < 0) {
		goto cleanup;
	}
	if ((tr->analyses & APOL_TYPES_RELATION_TYPE_RULES) && apol_types_relation_types(p, typeA, typeB, *r) < 0) {
		goto cleanup;
	}
	if ((tr->analyses & APOL_TYPES_RELATION_DIRECT_FLOW) && apol_types_relation_directflow(p, typeA, typeB, *r) < 0) {
		goto cleanup;
	}
	do_transAB = tr->analyses & APOL_TYPES_RELATION_TRANS_FLOW_AB;
	do_transBA = tr->analyses & APOL_TYPES_RELATION_TRANS_FLOW_BA;
	if ((do_transAB || do_transBA) && apol_types_relation_transflow(p, typeA, typeB, do_transAB, do_transBA, *r) < 0) {
		goto cleanup;
	}
	do_domainAB = tr->analyses & APOL_TYPES_RELATION_DOMAIN_TRANS_AB;
	do_domainBA = tr->analyses & APOL_TYPES_RELATION_DOMAIN_TRANS_BA;
	if ((do_domainAB || do_domainBA) && apol_types_relation_domain(p, typeA, typeB, do_domainAB, do_domainBA, *r) < 0) {
		goto cleanup;
	}

	retval = 0;
      cleanup:
	if (retval != 0) {
		apol_types_relation_result_destroy(r);
	}
	return retval;
}

apol_types_relation_analysis_t *apol_types_relation_analysis_create(void)
{
	return calloc(1, sizeof(apol_types_relation_analysis_t));
}

void apol_types_relation_analysis_destroy(apol_types_relation_analysis_t ** tr)
{
	if (*tr != NULL) {
		free((*tr)->typeA);
		free((*tr)->typeB);
		free(*tr);
		*tr = NULL;
	}
}

int apol_types_relation_analysis_set_first_type(const apol_policy_t * p, apol_types_relation_analysis_t * tr, const char *name)
{
	if (name == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		return -1;
	}
	return apol_query_set(p, &tr->typeA, NULL, name);
}

int apol_types_relation_analysis_set_other_type(const apol_policy_t * p, apol_types_relation_analysis_t * tr, const char *name)
{
	if (name == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		return -1;
	}
	return apol_query_set(p, &tr->typeB, NULL, name);
}

int apol_types_relation_analysis_set_analyses(const apol_policy_t * p __attribute__ ((unused)),
					      apol_types_relation_analysis_t * tr, unsigned int analyses)
{
	if (analyses != 0) {
		tr->analyses = analyses;
	} else {
		tr->analyses = ~0U;
	}
	return 0;
}

/*************** functions to access type relation results ***************/

void apol_types_relation_result_destroy(apol_types_relation_result_t ** result)
{
	if (*result != NULL) {
		apol_vector_destroy(&(*result)->attribs);
		apol_vector_destroy(&(*result)->roles);
		apol_vector_destroy(&(*result)->users);
		apol_vector_destroy(&(*result)->simA);
		apol_vector_destroy(&(*result)->simB);
		apol_vector_destroy(&(*result)->disA);
		apol_vector_destroy(&(*result)->disB);
		apol_vector_destroy(&(*result)->allows);
		apol_vector_destroy(&(*result)->types);
		apol_vector_destroy(&(*result)->dirflows);
		apol_vector_destroy(&(*result)->transAB);
		apol_vector_destroy(&(*result)->transBA);
		apol_vector_destroy(&(*result)->domsAB);
		apol_vector_destroy(&(*result)->domsBA);
		free(*result);
		*result = NULL;
	}
}

const apol_vector_t *apol_types_relation_result_get_attributes(const apol_types_relation_result_t * result)
{
	return result->attribs;
}

const apol_vector_t *apol_types_relation_result_get_roles(const apol_types_relation_result_t * result)
{
	return result->roles;
}

const apol_vector_t *apol_types_relation_result_get_users(const apol_types_relation_result_t * result)
{
	return result->users;
}

const apol_vector_t *apol_types_relation_result_get_similar_first(const apol_types_relation_result_t * result)
{
	return result->simA;
}

const apol_vector_t *apol_types_relation_result_get_similar_other(const apol_types_relation_result_t * result)
{
	return result->simB;
}

const apol_vector_t *apol_types_relation_result_get_dissimilar_first(const apol_types_relation_result_t * result)
{
	return result->disA;
}

const apol_vector_t *apol_types_relation_result_get_dissimilar_other(const apol_types_relation_result_t * result)
{
	return result->disB;
}

const apol_vector_t *apol_types_relation_result_get_allowrules(const apol_types_relation_result_t * result)
{
	return result->allows;
}

const apol_vector_t *apol_types_relation_result_get_typerules(const apol_types_relation_result_t * result)
{
	return result->types;
}

const apol_vector_t *apol_types_relation_result_get_directflows(const apol_types_relation_result_t * result)
{
	return result->dirflows;
}

const apol_vector_t *apol_types_relation_result_get_transflowsAB(const apol_types_relation_result_t * result)
{
	return result->transAB;
}

const apol_vector_t *apol_types_relation_result_get_transflowsBA(const apol_types_relation_result_t * result)
{
	return result->transBA;
}

const apol_vector_t *apol_types_relation_result_get_domainsAB(const apol_types_relation_result_t * result)
{
	return result->domsAB;
}

const apol_vector_t *apol_types_relation_result_get_domainsBA(const apol_types_relation_result_t * result)
{
	return result->domsBA;
}

const qpol_type_t *apol_types_relation_access_get_type(const apol_types_relation_access_t * a)
{
	return a->type;
}

const apol_vector_t *apol_types_relation_access_get_rules(const apol_types_relation_access_t * a)
{
	return a->rules;
}
