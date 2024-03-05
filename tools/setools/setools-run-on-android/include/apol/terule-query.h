/**
 * @file
 *
 * Routines to query type enforcement rules of a policy.  These are
 * type_transition, type_member, and type_change rules.
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

#ifndef APOL_TERULE_QUERY_H
#define APOL_TERULE_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include <qpol/policy.h>

	typedef struct apol_terule_query apol_terule_query_t;

/**
 * Execute a query against all type enforcement rules within the policy.
 *
 * @param p Policy within which to look up terules.
 * @param t Structure containing parameters for query.	If this is
 * NULL then return all terules.
 * @param v Reference to a vector of qpol_terule_t.  The vector will
 * be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_terule_get_by_query(const apol_policy_t * p, const apol_terule_query_t * t, apol_vector_t ** v);

/**
 * Execute a query against all syntactic type enforcement rules within
 * the policy.  If the policy has line numbers, then the returned list
 * will be sorted increasingly by line number.
 *
 * @param p Policy within which to look up terules. <b>Must be a
 * source policy.</b>
 * @param t Structure containing parameters for query.	If this is
 * NULL then return all terules.
 * @param v Reference to a vector of qpol_syn_terule_t.  The vector
 * will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_syn_terule_get_by_query(const apol_policy_t * p, const apol_terule_query_t * t, apol_vector_t ** v);

/**
 * Allocate and return a new terule query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all terules within the policy.  The caller must call
 * apol_terule_query_destroy() upon the return value afterwards.
 *
 * @return An initialized terule query structure, or NULL upon error.
 */
	extern apol_terule_query_t *apol_terule_query_create(void);

/**
 * Deallocate all memory associated with the referenced terule query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param t Reference to a terule query structure to destroy.
 */
	extern void apol_terule_query_destroy(apol_terule_query_t ** t);

/**
 * Set a terule query to search only certain type enforcement rules
 * within the policy.  This is a bitmap; use the constants in
 * libqpol/terule_query.h (QPOL_RULE_TYPE_TRANS, etc.) to give the
 * rule selections.
 *
 * @param p Policy handler, to report errors.
 * @param te TE rule query to set.
 * @param rules Bitmap to indicate which rules to search, or 0 to
 * search all rules.
 *
 * @return Always 0.
 */
	extern int apol_terule_query_set_rules(const apol_policy_t * p, apol_terule_query_t * t, unsigned int rules);

/**
 * Set a terule query to return rules whose source symbol matches
 * symbol.  Symbol may be a type or attribute; if it is an alias then
 * the query will convert it to its primary prior to searching.  If
 * is_indirect is non-zero then the search will be done indirectly.
 * If the symbol is a type, then the query matches rules with one of
 * the type's attributes.  If the symbol is an attribute, then it
 * matches rule with any of the attribute's types.
 *
 * @param p Policy handler, to report errors.
 * @param t TE rule query to set.
 * @param symbol Limit query to rules with this symbol as their
 * source, or NULL to unset this field.
 * @param is_indirect If non-zero, perform indirect matching.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_terule_query_set_source(const apol_policy_t * p, apol_terule_query_t * t, const char *symbol,
						int is_indirect);

/**
 * Set an terule query to return rules whose source symbol is matched as a type
 * or an attribute. The symbol will match both types and attributes by default.
 * @see apol_avrule_query_set_source() to set the symbol to match.
 *
 * @param p Policy handler, to report errors.
 * @param t TE rule query to set.
 * @param component Bit-wise or'ed set of APOL_QUERY_SYMBOL_IS_TYPE
 * and APOL_QUERY_SYMBOL_IS_ATTRIBUTE indicating the type of component
 * to match.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_terule_query_set_source_component(const apol_policy_t * p, apol_terule_query_t * t, unsigned int component);

/**
 * Set a terule query to return rules whose target symbol matches
 * symbol.  Symbol may be a type or attribute; if it is an alias then
 * the query will convert it to its primary prior to searching.  If
 * is_indirect is non-zero then the search will be done indirectly.
 * If the symbol is a type, then the query matches rules with one of
 * the type's attributes.  If the symbol is an attribute, then it
 * matches rule with any of the attribute's types.
 *
 * @param p Policy handler, to report errors.
 * @param t TE rule query to set.
 * @param symbol Limit query to rules with this symbol as their
 * target, or NULL to unset this field.
 * @param is_indirect If non-zero, perform indirect matching.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_terule_query_set_target(const apol_policy_t * p, apol_terule_query_t * t, const char *symbol,
						int is_indirect);

/**
 * Set an terule query to return rules whose target symbol is matched as a type
 * or an attribute. The symbol will match both types and attributes by default.
 * @see apol_avrule_query_set_source() to set the symbol to match.
 *
 * @param p Policy handler, to report errors.
 * @param t TE rule query to set.
 * @param component Bit-wise or'ed set of APOL_QUERY_SYMBOL_IS_TYPE
 * and APOL_QUERY_SYMBOL_IS_ATTRIBUTE indicating the type of component
 * to match.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_terule_query_set_target_component(const apol_policy_t * p, apol_terule_query_t * t, unsigned int component);

/**
 * Set a terule query to return rules with this default type.  The
 * symbol may be a type or any of its aliases; it may not be an
 * attribute.
 *
 * @param p Policy handler, to report errors.
 * @param t TE rule query to set.
 * @param type Name of default type to search.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_terule_query_set_default(const apol_policy_t * p, apol_terule_query_t * t, const char *type);

/**
 * Set at terule query to return rules with this object (non-common)
 * class.  If more than one class are appended to the query, the
 * rule's class must be one of those appended.  (I.e., the rule's
 * class must be a member of the query's classes.)  Pass a NULL to
 * clear all classes.  Note that this performs straight string
 * comparison, ignoring the regex flag.

 *
 * @param p Policy handler, to report errors.
 * @param t TE rule query to set.
 * @param obj_class Name of object class to add to search set.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_terule_query_append_class(const apol_policy_t * p, apol_terule_query_t * t, const char *obj_class);

/**
 * Set a terule query to return rules that are in conditionals and
 * whose conditional uses a particular boolean variable.
 * Unconditional rules will not be returned.
 *
 * @param p Policy handler, to report errors.
 * @param t TE rule query to set.
 * @param bool_name Name of boolean that conditional must contain.  If
 * NULL then search all rules.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_terule_query_set_bool(const apol_policy_t * p, apol_terule_query_t * t, const char *bool_name);

/**
 * Set a terule query to search only enabled rules within the policy.
 * These include rules that are unconditional and those within enabled
 * conditionals.
 *
 * @param p Policy handler, to report errors.
 * @param t TE rule query to set.
 * @param is_enabled Non-zero to search only enabled rules, 0 to
 * search all rules.
 *
 * @return Always 0.
 */
	extern int apol_terule_query_set_enabled(const apol_policy_t * p, apol_terule_query_t * t, int is_enabled);

/**
 * Set a terule query to treat the source symbol as any.  That is, use
 * the same symbol for either source, target, or default of a rule.
 * This flag does nothing if the source symbol is not set.
 *
 * @param p Policy handler, to report errors.
 * @param t TE rule query to set.
 * @param is_any Non-zero to use source symbol for any field, 0 to
 * keep source as only source.
 *
 * @return Always 0.
 */
	extern int apol_terule_query_set_source_any(const apol_policy_t * p, apol_terule_query_t * t, int is_any);

/**
 * Set a terule query to use regular expression searching for source
 * and target types/attributes and default type.  Strings will be
 * treated as regexes instead of literals.  Matching will occur against
 * the type name or any of its aliases.
 *
 * @param p Policy handler, to report errors.
 * @param t TE rule query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
	extern int apol_terule_query_set_regex(const apol_policy_t * p, apol_terule_query_t * t, int is_regex);

/**
 * Given a single terule, return a newly allocated vector of
 * qpol_syn_terule_t pointers (relative to the given policy) which
 * comprise that rule.  The vector will be sorted by line numbers if
 * the policy has line numbers.
 *
 * @param p Policy from which to obtain syntactic rules.
 * @param rule TE rule to convert.
 *
 * @return A newly allocated vector of syn_terule_t pointers.  The
 * caller is responsible for calling apol_vector_destroy() afterwards.
 */
	extern apol_vector_t *apol_terule_to_syn_terules(const apol_policy_t * p, const qpol_terule_t * rule);

/**
 * Given a vector of terules (qpol_terule_t pointers), return a newly
 * allocated vector of qpol_syn_terule_t pointers (relative to the
 * given policy) which comprise all of those rules.  The returned
 * vector will be sorted by line numbers if the policy has line
 * numbers.  Also, it will not have any duplicate syntactic rules.
 *
 * @param p Policy from which to obtain syntactic rules.
 * @param rules Vector of TE rules to convert.
 *
 * @return A newly allocated vector of syn_terule_t pointers.  The
 * caller is responsible for calling apol_vector_destroy() afterwards.
 */
	extern apol_vector_t *apol_terule_list_to_syn_terules(const apol_policy_t * p, const apol_vector_t * rules);

/**
 *  Render a terule to a string.
 *
 *  @param policy Policy handler, to report errors.
 *  @param rule The rule to render.
 *
 *  @return a newly malloc()'d string representation of the rule, or NULL on
 *  failure; if the call fails, errno will be set. The caller is responsible
 *  for calling free() on the returned string.
 */
	extern char *apol_terule_render(const apol_policy_t * policy, const qpol_terule_t * rule);

/**
 *  Render a syntactic terule to a string.
 *
 *  @param policy Policy handler to report errors.
 *  @param rule The rule to render.
 *
 *  @return a newly malloc()'d string representation of the rule, or NULL on
 *  failure; if the call fails, errno will be set. The caller is responsible
 *  for calling free() on the returned string.
*/
	extern char *apol_syn_terule_render(const apol_policy_t * policy, const qpol_syn_terule_t * rule);

#ifdef	__cplusplus
}
#endif

#endif
