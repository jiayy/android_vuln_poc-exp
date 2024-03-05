/**
 * @file
 *
 * Header for routines shared among libapol's queries and analyses.
 * These routines are declared hidden within the library by way of the
 * linking map.
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

#ifndef APOL_POLICY_QUERY_INTERNAL_H
#define APOL_POLICY_QUERY_INTERNAL_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <config.h>

#include <apol/policy.h>
#include <apol/policy-query.h>
#include <apol/util.h>
#include <apol/vector.h>

#include <regex.h>
#include <stdlib.h>
#include <qpol/policy.h>

/* forward declaration. the definition resides within perm-map.c */
	struct apol_permmap;

/* forward declaration. the definition resides within domain-trans-analysis.c */
	typedef struct apol_domain_trans_table apol_domain_trans_table_t;

/* declared in perm-map.c */
	typedef struct apol_permmap apol_permmap_t;

	struct apol_policy
	{
		qpol_policy_t *p;
		apol_callback_fn_t msg_callback;
		void *msg_callback_arg;
		int policy_type;
	/** permission mapping for this policy; mappings loaded as needed */
		struct apol_permmap *pmap;
	/** for domain trans analysis; table built as needed */
		struct apol_domain_trans_table *domain_trans_table;
	};

/** Every query allows the treatment of strings as regular expressions
 *  instead.  Within the query structure are flags; if the first bit
 *  is set then use regex matching instead. */
#define APOL_QUERY_REGEX 0x01

#define APOL_QUERY_ONLY_ENABLED 0x10
#define APOL_QUERY_SOURCE_AS_ANY 0x20
#define APOL_QUERY_SOURCE_INDIRECT 0x40
#define APOL_QUERY_TARGET_INDIRECT 0x80

#define APOL_QUERY_SYMBOL_IS_BOTH (APOL_QUERY_SYMBOL_IS_TYPE|APOL_QUERY_SYMBOL_IS_ATTRIBUTE)
#define APOL_QUERY_SOURCE_TYPE 0x100
#define APOL_QUERY_SOURCE_ATTRIBUTE 0x200
#define APOL_QUERY_TARGET_TYPE 0x400
#define APOL_QUERY_TARGET_ATTRIBUTE 0x800

#define APOL_QUERY_MATCH_ALL_PERMS 0x1000

/**
 * Destroy a compiled regular expression, setting it to NULL
 * afterwards.	Does nothing if the reference is NULL.
 * @param regex Regular expression to destroy.
 */
	void apol_regex_destroy(regex_t ** regex);

/**
 * Sets a string field within a query, clearing its old contents and
 * cached regex first.	The search name will be duplicated.
 *
 * @param p Policy handler.
 * @param search_name Reference to where to store duplicated name.
 * @param regex Reference to cached regex; this will be cleared by the
 * function.
 * @param name New name to set, or NULL to just clear the field.
 *
 * @return 0 on success, < 0 on error.
 */
	int apol_query_set(const apol_policy_t * p, char **query_name, regex_t ** regex, const char *name);

/**
 * Sets an arbitrary flag for a query structure.
 *
 * @param p Policy handler.
 * @param flags Reference to a flag bitmap.
 * @param is_flag If non-zero, set flag. Otherwise unset it.
 * @param flag_value Flag value to set.
 *
 * @return Always returns 0.
 */
	int apol_query_set_flag(const apol_policy_t * p, unsigned int *flags, const int is_flag, int flag_value);

/**
 * Sets the regular expression flag for a query structure.
 *
 * @param p Policy handler.
 * @param flags Reference to the regular expression flag.
 * @param is_regex If non-zero, set regex flag.	 Otherwise unset it.
 *
 * @return Always returns 0.
 */
	int apol_query_set_regex(const apol_policy_t * p, unsigned int *flags, const int is_regex);

/**
 * Determines if a name matches a target symbol name.  If flags has
 * the APOL_QUERY_REGEX bit set, then (1) compile the regular
 * expression if NULL, and (2) apply it to target.  Otherwise do a
 * string comparison between name and target.  If name is NULL and/or
 * empty then the comparison always succeeds regardless of flags and
 * regex.
 *
 * @param p Policy handler.
 * @param target Name of target symbol to compare.
 * @param name Source target from which to compare.
 * @param flags If APOL_QUERY_REGEX bit is set, treat name as a
 * regular expression.
 * @param regex If using regexp comparison, the compiled regular
 * expression to use; the pointer will be allocated space if regexp is
 * legal.  If NULL, then compile the regexp pattern given by name and
 * cache it here.
 *
 * @return 1 If comparison succeeds, 0 if not; < 0 on error.
 */
	int apol_compare(const apol_policy_t * p, const char *target, const char *name, unsigned int flags, regex_t ** regex);

/**
 * Given an iterator of strings, checks if name matches any element
 * within it.  If there is a match, either literally or by regular
 * expression, then return 1.  If there are no matches then return 0.
 *
 * @param p Policy handler.
 * @param iter Iterator of strings to match.
 * @param name Source target from which to compare.
 * @param flags If APOL_QUERY_REGEX bit is set, treat name as a
 * regular expression.
 * @param regex If using regexp comparison, the compiled regular
 * expression to use; the pointer will be allocated space if regexp is
 * legal.  If NULL, then compile the regexp pattern given by name and
 * cache it here.
 * @param do_free If non-zero free the strings returned by the iterator.
 *
 * @return 1 If comparison succeeds, 0 if not; < 0 on error.
 */
	int apol_compare_iter(const apol_policy_t * p, qpol_iterator_t * iter, const char *name,
			      unsigned int flags, regex_t ** regex, int do_free);

/**
 * Determines if a (partial) type query matches a qpol_type_t,
 * either the type name or any of its aliases.
 *
 * @param p Policy within which to look up types.
 * @param type Type datum to compare against.
 * @param name Source target from which to compare.
 * @param flags If APOL_QUERY_REGEX bit is set, treat name as a
 * regular expression.
 * @param regex If using regexp comparison, the compiled regular
 * expression to use; the pointer will be allocated space if regexp is
 * legal.  If NULL, then compile the regexp pattern given by name and
 * cache it here.
 *
 * @return 1 If comparison succeeds, 0 if not; < 0 on error.
 */
	int apol_compare_type(const apol_policy_t * p, const qpol_type_t * type, const char *name, unsigned int flags,
			      regex_t ** type_regex);

/**
 * Determines if a (partial) permissive query matches a qpol_permissive_t,
 * by name.
 *
 * @param p Policy within which to look up types.
 * @param type Permissive datum to compare against.
 * @param name Source target from which to compare.
 * @param flags If APOL_QUERY_REGEX bit is set, treat name as a
 * regular expression.
 * @param regex If using regexp comparison, the compiled regular
 * expression to use; the pointer will be allocated space if regexp is
 * legal.  If NULL, then compile the regexp pattern given by name and
 * cache it here.
 *
 * @return 1 If comparison succeeds, 0 if not; < 0 on error.
 */
	int apol_compare_permissive(const apol_policy_t * p, const qpol_permissive_t * permissive, const char *name, unsigned int flags,
			      regex_t ** type_regex);

/**
 * Determines if a (partial) polcap query matches a qpol_polcap_t,
 * by name.
 *
 * @param p Policy within which to look up types.
 * @param type Polcap datum to compare against.
 * @param name Source target from which to compare.
 * @param flags If APOL_QUERY_REGEX bit is set, treat name as a
 * regular expression.
 * @param regex If using regexp comparison, the compiled regular
 * expression to use; the pointer will be allocated space if regexp is
 * legal.  If NULL, then compile the regexp pattern given by name and
 * cache it here.
 *
 * @return 1 If comparison succeeds, 0 if not; < 0 on error.
 */
	int apol_compare_polcap(const apol_policy_t * p, const qpol_polcap_t * polcap, const char *name, unsigned int flags,
			      regex_t ** type_regex);

/**
 * Determines if a boolean is used within a particual conditional.
 *
 * @param p Policy within which to look up types.
 * @param cond Conditional to compare against.
 * @param name Source boolean name from which to compare.
 * @param flags If APOL_QUERY_REGEX bit is set, treat name as a
 * regular expression.
 * @param regex If using regexp comparison, the compiled regular
 * expression to use; the pointer will be allocated space if regexp is
 * legal.  If NULL, then compile the regexp pattern given by name and
 * cache it here.
 *
 * @return 1 If comparison succeeds, 0 if not; < 0 on error.
 */
	int apol_compare_cond_expr(const apol_policy_t * p, const qpol_cond_t * cond, const char *name, unsigned int flags,
				   regex_t ** bool_regex);

/**
 * Determines if a level query matches a qpol_level_t, either
 * the sensitivity name or any of its aliases.
 *
 * @param p Policy within which to look up types.
 * @param level level datum to compare against.
 * @param name Source target from which to compare.
 * @param flags If APOL_QUERY_REGEX bit is set, treat name as a
 * regular expression.
 * @param regex If using regexp comparison, the compiled regular
 * expression to use; the pointer will be allocated space if regexp is
 * legal.  If NULL, then compile the regexp pattern given by name and
 * cache it here.
 *
 * @return 1 If comparison succeeds, 0 if not; < 0 on error.
 */
	int apol_compare_level(const apol_policy_t * p, const qpol_level_t * level, const char *name, unsigned int flags,
			       regex_t ** level_regex);

/**
 * Determines if a category query matches a qpol_cat_t, either
 * the category name or any of its aliases.
 *
 * @param p Policy within which to look up types.
 * @param cat category datum to compare against.
 * @param name Source target from which to compare.
 * @param flags If APOL_QUERY_REGEX bit is set, treat name as a
 * regular expression.
 * @param regex If using regexp comparison, the compiled regular
 * expression to use; the pointer will be allocated space if regexp is
 * legal.  If NULL, then compile the regexp pattern given by name and
 * cache it here.
 *
 * @return 1 If comparison succeeds, 0 if not; < 0 on error.
 */
	int apol_compare_cat(const apol_policy_t * p, const qpol_cat_t * cat, const char *name, unsigned int flags,
			     regex_t ** cat_regex);

/**
 * Convenience function that compares a qpol_context_t to a
 * apol_context_t, based upon the MLS range match given by flags.  If
 * search is NULL then the comparison always succeeds.
 *
 * @param p Policy within which to look up types.
 * @param target Target context to compare.
 * @param name Source context from which to compare.
 * @param flags Gives how to match MLS ranges within the contexts.
 *
 * @return 1 If comparison succeeds, 0 if not; < 0 on error.
 */
	int apol_compare_context(const apol_policy_t * p, const qpol_context_t * target, const apol_context_t * search,
				 unsigned int flags);

/**
 * Given a type name, obtain its qpol_type_t pointer (relative to a
 * policy).  If the type is really its alias, get its primary instead.
 * (Attributes are considered to be always primary.)
 *
 * @param p Policy in which to look up types.
 * @param type_name Name of type to find.
 * @param type Reference to where to store resulting pointer.
 *
 * @return 0 on success, < 0 on error.
 */
	int apol_query_get_type(const apol_policy_t * p, const char *type_name, const qpol_type_t ** type);

/**
 * Given a symbol name (a type, attribute, alias, or a regular
 * expression string), determine all types/attributes it matches.
 * Return a vector of qpol_type_t that match.  If regex is enabled,
 * include all types/attributes that match the expression.  If
 * indirect is enabled, expand the candidiates within the vector (all
 * attributes for a type, all types for an attribute), and then
 * uniquify the vector.
 *
 * @param p Policy in which to look up types.
 * @param symbol A string describing one or more type/attribute to
 * which match.
 * @param do_regex If non-zero, then treat symbol as a regular expression.
 * @param do_indirect If non-zero, expand types to their attributes
 * and attributes to their types.
 * @param ta_flag Bit-wise or of (APOL_QUERY_SYMBOL_IS_TYPE,
 * APOL_QUERY_SYMBOL_IS_ATTRIBUTE, APOL_QUERY_SYMBOL_IS_BOTH) whether
 * symbol should be matched against type names or attribute names.
 *
 * @return Vector of unique qpol_type_t pointers (relative to policy
 * within p), or NULL upon error.  Caller is responsible for calling
 * apol_vector_destroy() afterwards.
 */
	apol_vector_t *apol_query_create_candidate_type_list(const apol_policy_t * p, const char *symbol, int do_regex,
							     int do_indirect, unsigned int ta_flag);

/**
 * Given a symbol name (a type, attribute, alias, or a regular
 * expression string), determine all types/attributes it matches.
 * Return a vector of qpol_type_t that match.  If regex is enabled,
 * include all types/attributes that match the expression.  If
 * indirect is enabled, expand the candidiates within the vector (all
 * attributes for a type, all types for an attribute), and then
 * uniquify the vector. The list will include types needed for syntactic
 * rule searching.
 *
 * @param p Policy in which to look up types. <b>Must be a source policy.</b>
 * @param symbol A string describing one or more type/attribute to
 * which match.
 * @param do_regex If non-zero, then treat symbol as a regular expression.
 * @param do_indirect If non-zero, expand types to their attributes
 * and attributes to their types.
 * @param ta_flag Bit-wise or of (APOL_QUERY_SYMBOL_IS_TYPE,
 * APOL_QUERY_SYMBOL_IS_ATTRIBUTE, APOL_QUERY_SYMBOL_IS_BOTH) whether
 * symbol should be matched against type names or attribute names.
 *
 * @return Vector of unique qpol_type_t pointers (relative to policy
 * within p), or NULL upon error.  Caller is responsible for calling
 * apol_vector_destroy() afterwards.
 */
	apol_vector_t *apol_query_create_candidate_syn_type_list(const apol_policy_t * p, const char *symbol, int do_regex,
								 int do_indirect, unsigned int ta_flag);

/**
 * Given a symbol name (a role or a regular expression string),
 * determine all roles it matches.  Return a vector of qpol_role_t
 * that match.  If regex is enabled, include all role that
 * match the expression.
 *
 * @param p Policy in which to look up roles.
 * @param symbol A string describing one or more role to match.
 * @param do_regex If non-zero, then treat symbol as a regular expression.
 *
 * @return Vector of unique qpol_role_t pointers (relative to policy
 * within p), or NULL upon error.  Caller is responsible for calling
 * apol_vector_destroy() afterwards.
 */
	apol_vector_t *apol_query_create_candidate_role_list(const apol_policy_t * p, char *symbol, int do_regex);

/**
 * Given a vector of object class strings, determine all of the
 * classes it matches within the policy.  Returns a vector of
 * qpol_class_t that match.  If a string does not match an object
 * class within the policy then it is ignored.
 *
 * @param p Policy in which to look up classes.
 * @param classes Vector of class strings to convert.
 *
 * @return Vector of unique qpol_class_t pointers (relative to policy
 * within p), or NULL upon error.  Caller is responsible for calling
 * apol_vector_destroy() afterwards.
 */
	apol_vector_t *apol_query_create_candidate_class_list(const apol_policy_t * p, apol_vector_t * classes);

/**
 * Given a type, return a vector of qpol_type_t pointers to which the
 * type expands.  If the type is just a type or an alias, the vector
 * will have one element, pointing to the type's primary.  If it was
 * an attribute, the vector will have that attribute's types (but not
 * the attribute itself).
 *
 * @param p Policy in which to look up types.
 * @param t Type to expand.
 *
 * @return Vector of qpol_type_t pointers, or NULL upon error.  Caller
 * is responsible for calling apol_vector_destroy() afterwards.
 */
	apol_vector_t *apol_query_expand_type(const apol_policy_t * p, const qpol_type_t * t);

/**
 *  Object class and permission set.
 *  Contains the name of a class and a list of permissions
 *  used by analyses and complex searches to allow permissions
 *  to be specified on a per class basis.
 */
	typedef struct apol_obj_perm apol_obj_perm_t;

/**
 *  Allocate and return a new object permission set.
 *  @return a newly allocated object permission set or NULL on error.
 *  Caller is responsible for calling apol_obj_perm_free() to free
 *  memory used.
 */
	apol_obj_perm_t *apol_obj_perm_create(void);

/**
 *  Free the memory used by an object permission set.
 *  @param op the object permission set to free.
 */
	void apol_obj_perm_free(void *op);

/**
 *  Set the object class name for an object permission set.
 *  If already set free the previous name.
 *  @param op The object permission set for which to set the object name.
 *  @param obj_name New object name to set; this string will be duplicated
 *  by this call. If NULL only free existing name (if any).
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and the original object permission set will be unchanged.
 */
	int apol_obj_perm_set_obj_name(apol_obj_perm_t * op, const char *obj_name);

/**
 *  Get the object class name from an object permission set.
 *  @param op The object permission set from which to get the class name.
 *  @return The class name or NULL if not set or error. The caller <b>should
 *  NOT</b> free the returned string.
 */
	char *apol_obj_perm_get_obj_name(const apol_obj_perm_t * op);

/**
 *  Add a permission to the permission list of an object permission set.
 *  @param op The object permission set to which to add the permission.
 *  @param perm Name of the permission to add, this string will be duplicated.
 *  If NULL clear all permissions. If the permission is already in the list
 *  nothing is done;
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and the original object permission set will be unchanged.
 */
	int apol_obj_perm_append_perm(apol_obj_perm_t * op, const char *perm);

/**
 *  Get a vector of the permissions in an object permission set.
 *  @param op The object permission set from which to get the permissions.
 *  @return Vector (of type char *) of permission names; the caller
 *  <b>should NOT</b> destroy this vector.
 */
	apol_vector_t *apol_obj_perm_get_perm_vector(const apol_obj_perm_t * op);

/**
 *  Comparision function for use with vectors of object permission sets.
 *  @param a first object permission set.
 *  @param b second object permission set.
 *  @param policy apol policy from which the objects and permissions come.
 *  @return < 0, 0, or > 0 if the value of the class of a is less than, equal
 *  to, or greater than that of b respectively.
 */
	int apol_obj_perm_compare_class(const void *a, const void *b, void *policy);

/**
 *  Determine if a syntactic type set directly uses any of the types in v.
 *  @param p Policy from which the type set and types come.
 *  @param set Syntactic type set to check.
 *  @param v Vector of types (qpol_type_t) to find in set.
 *  @return 0 if no types in v appear in set, > 0 if at least one type
 *  was found, and < 0 if an error occurred.
 */
	int apol_query_type_set_uses_types_directly(const apol_policy_t * p, const qpol_type_set_t * set, const apol_vector_t * v);

/**
 * Deallocate all space associated with a particular policy's permmap,
 * including the pointer itself.  Afterwards set the pointer to NULL.
 *
 * @param p Reference to an apol_permmap_t to destroy.
 */
	void permmap_destroy(apol_permmap_t ** p);

/**
 *  Destroy the domain transition table freeing all memory used.
 *  @param table Reference pointer to the table to be destroyed.
 */
	void domain_trans_table_destroy(apol_domain_trans_table_t ** table);

#ifdef	__cplusplus
}
#endif

#endif
