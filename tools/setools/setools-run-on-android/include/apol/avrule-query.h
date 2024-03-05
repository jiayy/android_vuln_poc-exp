/**
 * @file
 *
 * Routines to query access vector rules of a policy.  These are
 * allow, neverallow, auditallow, and dontaudit rules.
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

#ifndef APOL_AVRULE_QUERY_H
#define APOL_AVRULE_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include <qpol/policy.h>

	typedef struct apol_avrule_query apol_avrule_query_t;

/**
 * Execute a query against all access vector rules within the policy.
 *
 * @param p Policy within which to look up avrules.
 * @param a Structure containing parameters for query.	If this is
 * NULL then return all avrules.
 * @param v Reference to a vector of qpol_avrule_t.  The vector will
 * be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_avrule_get_by_query(const apol_policy_t * p, const apol_avrule_query_t * a, apol_vector_t ** v);

/**
 * Execute a query against all syntactic access vector rules within
 * the policy.  If the policy has line numbers, then the returned list
 *
 * @param p Policy within which to look up avrules.  The policy must
 * be capable of having syntactic rules.
 * @param a Structure containing parameters for query. If this is
 * NULL then return all avrules.
 * @param v Reference to a vector of qpol_syn_avrule_t.  The vector
 * will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_syn_avrule_get_by_query(const apol_policy_t * p, const apol_avrule_query_t * a, apol_vector_t ** v);

/**
 * Allocate and return a new avrule query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all avrules within the policy.  The caller must call
 * apol_avrule_query_destroy() upon the return value afterwards.
 *
 * @return An initialized avrule query structure, or NULL upon error.
 */
	extern apol_avrule_query_t *apol_avrule_query_create(void);

/**
 * Deallocate all memory associated with the referenced avrule query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param a Reference to a avrule query structure to destroy.
 */
	extern void apol_avrule_query_destroy(apol_avrule_query_t ** a);

/**
 * Set an avrule query to search only certain access vector rules
 * within the policy.  This is a bitmap; use the constants in
 * libqpol/avrule_query.h (QPOL_RULE_ALLOW, etc.) to give the rule
 * selections.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param rules Bitmap to indicate which rules to search, or 0 to
 * search all rules.
 *
 * @return Always 0.
 */
	extern int apol_avrule_query_set_rules(const apol_policy_t * p, apol_avrule_query_t * a, unsigned int rules);

/**
 * Set an avrule query to return rules whose source symbol matches
 * symbol.  Symbol may be a type or attribute; if it is an alias then
 * the query will convert it to its primary prior to searching.  If
 * is_indirect is non-zero then the search will be done indirectly.
 * If the symbol is a type, then the query matches rules with one of
 * the type's attributes.  If the symbol is an attribute, then it
 * matches rule with any of the attribute's types.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param symbol Limit query to rules with this symbol as their
 * source, or NULL to unset this field.
 * @param is_indirect If non-zero, perform indirect matching.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_avrule_query_set_source(const apol_policy_t * p, apol_avrule_query_t * a, const char *symbol,
						int is_indirect);

/**
 * Set an avrule query to return rules whose source symbol is matched as a type
 * or an attribute. The symbol will match both types and attributes by default.
 * @see apol_avrule_query_set_source() to set the symbol to match.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param component Bit-wise or'ed set of APOL_QUERY_SYMBOL_IS_TYPE
 * and APOL_QUERY_SYMBOL_IS_ATTRIBUTE indicating the type of component
 * to match.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_avrule_query_set_source_component(const apol_policy_t * p, apol_avrule_query_t * a, unsigned int component);

/**
 * Set an avrule query to return rules whose target symbol matches
 * symbol.  Symbol may be a type or attribute; if it is an alias then
 * the query will convert it to its primary prior to searching.  If
 * is_indirect is non-zero then the search will be done indirectly.
 * If the symbol is a type, then the query matches rules with one of
 * the type's attributes.  If the symbol is an attribute, then it
 * matches rule with any of the attribute's types.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param symbol Limit query to rules with this symbol as their
 * target, or NULL to unset this field.
 * @param is_indirect If non-zero, perform indirect matching.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_avrule_query_set_target(const apol_policy_t * p, apol_avrule_query_t * a, const char *symbol,
						int is_indirect);

/**
 * Set an avrule query to return rules whose target symbol is matched as a type
 * or an attribute. The symbol will match both types and attributes by default.
 * @see apol_avrule_query_set_target() to set the symbol to match.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param component Bit-wise or'ed set of APOL_QUERY_SYMBOL_IS_TYPE
 * and APOL_QUERY_SYMBOL_IS_ATTRIBUTE indicating the type of component
 * to match.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_avrule_query_set_target_component(const apol_policy_t * p, apol_avrule_query_t * a, unsigned int component);

/**
 * Set an avrule query to return rules with this object (non-common)
 * class.  If more than one class are appended to the query, the
 * rule's class must be one of those appended.  (I.e., the rule's
 * class must be a member of the query's classes.)  Pass a NULL to
 * clear all classes.  Note that this performs straight string
 * comparison, ignoring the regex flag.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param obj_class Name of object class to add to search set, or NULL
 * to clear all classes.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_avrule_query_append_class(const apol_policy_t * p, apol_avrule_query_t * a, const char *obj_class);

/**
 * Set an avrule query to return rules with this permission.  By
 * default, if more than one permission are appended to the query, at
 * least one of the rule's permissions must be one of those appended;
 * that is, the intersection of query's and rule's permissions must be
 * non-empty.  (This behavior can be changed.)  Pass a NULL to clear
 * all permissions.  Note that this performs a straight string
 * comparison, ignoring the regex flag.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param perm Name of permission to add to search set, or NULL to
 * clear all permissions.
 *
 * @return 0 on success, negative on error.
 *
 * @see apol_avrule_query_set_all_perms()
 */
	extern int apol_avrule_query_append_perm(const apol_policy_t * p, apol_avrule_query_t * a, const char *perm);

/**
 * Set an avrule query to return rules that are in conditionals and
 * whose conditional uses a particular boolean variable.
 * Unconditional rules will not be returned.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param bool_name Name of boolean that conditional must contain.  If
 * NULL then search all rules.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_avrule_query_set_bool(const apol_policy_t * p, apol_avrule_query_t * a, const char *bool_name);

/**
 * Set an avrule query to search only enabled rules within the policy.
 * These include rules that are unconditional and those within enabled
 * conditionals.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param is_enabled Non-zero to search only enabled rules, 0 to
 * search all rules.
 *
 * @return Always 0.
 */
	extern int apol_avrule_query_set_enabled(const apol_policy_t * p, apol_avrule_query_t * a, int is_enabled);

/**
 * Normally, if more than one permission are added to the query then
 * all returned rules will have <em>at least one</em> of those
 * permissions.  If the all_perms flag is set, then returned rules
 * will have <em>all</em> of the given permissions.  This flag does
 * nothing if no permissions are given.
 *
 * <em>Note:</em> If calling apol_syn_avrule_get_by_query(), the
 * returned results may not be what is expected.  For a given
 * source-target-class triplet, all of the associated permissions are
 * unioned together prior to executing the avrule query.  Although a
 * given syntactic AV rule might not have all of the matched
 * permissions, the union of the rules' permissions will them.  For
 * example, consider these two allow rules:
 *
 *<pre>allow A B : C p1;
 *allow A B : C p2;</pre>
 *
 * If the avrule query has both permissions p1 and p2 and the
 * all_perms flag is set, then both of these syntactic rules will be
 * returned by apol_syn_avrule_get_by_query().
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param all_perms Non-zero to match all permissions, zero to match
 * any permission.
 *
 * @return Always 0.
 *
 * @see apol_avrule_query_append_perm()
 */
	extern int apol_avrule_query_set_all_perms(const apol_policy_t * p, apol_avrule_query_t * a, int all_perms);

/**
 * Set an avrule query to treat the source symbol as any.  That is,
 * use the same symbol for either source or target of a rule.  This
 * flag does nothing if the source symbol is not set.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param is_any Non-zero to use source symbol for any field, 0 to
 * keep source as only source.
 *
 * @return Always 0.
 */
	extern int apol_avrule_query_set_source_any(const apol_policy_t * p, apol_avrule_query_t * a, int is_any);

/**
 * Set an avrule query to use regular expression searching for source
 * and target types/attributes.  Strings will be treated as regexes
 * instead of literals.  Matching will occur against the type name or
 * any of its aliases.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
	extern int apol_avrule_query_set_regex(const apol_policy_t * p, apol_avrule_query_t * a, int is_regex);

/**
 * Given a single avrule, return a newly allocated vector of
 * qpol_syn_avrule_t pointers (relative to the given policy) which
 * comprise that rule.  The vector will be sorted by line numbers if
 * the policy has line numbers.  If the given perms vector is non-NULL
 * and non-empty, then only return syntactic rules with at least one
 * permission listed within the perms vector.
 *
 * @param p Policy from which to obtain syntactic rules.
 * @param rule AV rule to convert.
 * @param perms If non-NULL and non-empty, a list of permission
 * strings.  Returned syn avrules will have at least one permission in
 * common with this list.
 *
 * @return A newly allocated vector of syn_avrule_t pointers.  The
 * caller is responsible for calling apol_vector_destroy() afterwards.
 */
	extern apol_vector_t *apol_avrule_to_syn_avrules(const apol_policy_t * p, const qpol_avrule_t * rule,
							 const apol_vector_t * perms);

/**
 * Given a vector of avrules (qpol_avrule_t pointers), return a newly
 * allocated vector of qpol_syn_avrule_t pointers (relative to the
 * given policy) which comprise all of those rules.  The returned
 * vector will be sorted by line numbers if the policy has line
 * numbers.  Also, it will not have any duplicate syntactic rules.  If
 * the given perms vector is non-NULL and non-empty, then only return
 * syntactic rules with at least one permission listed within the
 * perms vector.
 *
 * @param p Policy from which to obtain syntactic rules.
 * @param rules Vector of AV rules to convert.
 * @param perms If non-NULL and non-empty, a list of permission
 * strings.  Returned syn avrules will have at least one permission in
 * common with this list.
 *
 * @return A newly allocated vector of syn_avrule_t pointers.  The
 * caller is responsible for calling apol_vector_destroy() afterwards.
 */
	extern apol_vector_t *apol_avrule_list_to_syn_avrules(const apol_policy_t * p, const apol_vector_t * rules,
							      const apol_vector_t * perms);

/**
 *  Render an avrule to a string.
 *
 *  @param policy Policy handler, to report errors.
 *  @param rule The rule to render.
 *
 *  @return a newly malloc()'d string representation of the rule, or NULL on
 *  failure; if the call fails, errno will be set. The caller is responsible
 *  for calling free() on the returned string.
 */
	extern char *apol_avrule_render(const apol_policy_t * policy, const qpol_avrule_t * rule);

/**
 *  Render a syntactic avrule to a string.
 *
 *  @param policy Policy handler to report errors.
 *  @param rule The rule to render.
 *
 *  @return a newly malloc()'d string representation of the rule, or NULL on
 *  failure; if the call fails, errno will be set. The caller is responsible
 *  for calling free() on the returned string.
*/
	extern char *apol_syn_avrule_render(const apol_policy_t * policy, const qpol_syn_avrule_t * rule);

#ifdef	__cplusplus
}
#endif

#endif
