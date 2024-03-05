/**
 * @file
 *
 * Routines to query filename_transition rules of a
 * policy.  
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

#ifndef APOL_FTRULE_QUERY_H
#define APOL_FTRULE_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include <qpol/policy.h>

	typedef struct apol_filename_trans_query apol_filename_trans_query_t;


/******************** filename_transition queries ********************/

/**
 * Execute a query against all filename_transition rules within the
 * policy.
 *
 * @param p Policy within which to look up filename_transition rules.
 * @param r Structure containing parameters for query.	If this is
 * NULL then return all filename_transition rules.
 * @param v Reference to a vector of qpol_filename_trans_t.  The vector
 * will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_filename_trans_get_by_query(const apol_policy_t * p, const apol_filename_trans_query_t * r, apol_vector_t ** v);

/**
 * Allocate and return a new filename trans query structure.  All fields
 * are initialized, such that running this blank query results in
 * returning all filename_transitions within the policy.  The caller must
 * call apol_filename_trans_query_destroy() upon the return value
 * afterwards.
 *
 * @return An initialized filename trans query structure, or NULL upon
 * error.
 */
	extern apol_filename_trans_query_t *apol_filename_trans_query_create(void);

/**
 * Deallocate all memory associated with the referenced filename trans
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param r Reference to a filename trans query structure to destroy.
 */
	extern void apol_filename_trans_query_destroy(apol_filename_trans_query_t ** r);

/**
 * Set a filename_trans query to return rules whose source symbol matches
 * symbol.  Symbol may be a type or attribute; if it is an alias then
 * the query will convert it to its primary prior to searching.  If
 * is_indirect is non-zero then the search will be done indirectly.
 * If the symbol is a type, then the query matches rules with one of
 * the type's attributes.  If the symbol is an attribute, then it
 * matches rule with any of the attribute's types.
 *
 * @param p Policy handler, to report errors.
 * @param t FT rule query to set.
 * @param symbol Limit query to rules with this symbol as their
 * source, or NULL to unset this field.
 * @param is_indirect If non-zero, perform indirect matching.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_filename_trans_query_set_source(const apol_policy_t * p, apol_filename_trans_query_t * t, const char *symbol,
						int is_indirect);

/**
 * Set a filename trans query to return rules with a particular target
 * symbol.  Symbol may be a type or attribute; if it is an alias then
 * the query will convert it to its primary prior to searching.  If
 * is_indirect is non-zero then the search will be done indirectly.
 * If the symbol is a type, then the query matches rules with one of
 * the type's attributes.  If the symbol is an attribute, then it
 * matches rule with any of the attribute's types.
 *
 * @param p Policy handler, to report errors.
 * @param r FT rule query to set.
 * @param symbol Limit query to rules with this type or attribute as
 * their target, or NULL to unset this field.
 * @param is_indirect If non-zero, perform indirect matching.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_filename_trans_query_set_target(const apol_policy_t * p, apol_filename_trans_query_t * r, const char *symbol,
						    int is_indirect);

/**
 * Set a filename trans query to return rules with a particular default
 * filename.  This field is ignored if
 * apol_filename_trans_query_set_source_any() is set to non-zero.
 *
 * @param p Policy handler, to report errors.
 * @param r FT rule query to set.
 * @param filename Limit query to rules with this filename as their default, or
 * NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_filename_trans_query_set_default(const apol_policy_t * p, apol_filename_trans_query_t * r, const char *filename);

/**
 * Set at filename_trans query to return rules with this object (non-common)
 * class.  If more than one class are appended to the query, the
 * rule's class must be one of those appended.  (I.e., the rule's
 * class must be a member of the query's classes.)  Pass a NULL to
 * clear all classes.  Note that this performs straight string
 * comparison, ignoring the regex flag.

 *
 * @param p Policy handler, to report errors.
 * @param t FT rule query to set.
 * @param obj_class Name of object class to add to search set.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_filename_trans_query_append_class(const apol_policy_t * p, apol_filename_trans_query_t * t, const char *obj_class);

/**
 * Set a filename trans query to treat the source filename as any.  That is,
 * use the same symbol for either source or default of a
 * filename_transition rule.  This flag does nothing if the source filename is
 * not set.  Note that a filename_transition's target is a type, so thus
 * this flag does not affect its searching.
 *
 * @param p Policy handler, to report errors.
 * @param r FT rule query to set.
 * @param is_any Non-zero to use source symbol for source or default
 * field, 0 to keep source as only source.
 *
 * @return Always 0.
 */
	extern int apol_filename_trans_query_set_source_any(const apol_policy_t * p, apol_filename_trans_query_t * r, int is_any);

/**
 * Set a filename trans query to use regular expression searching for
 * source, target, and default fields.  Strings will be treated as
 * regexes instead of literals.  For the target type, matching will
 * occur against the type name or any of its aliases.
 *
 * @param p Policy handler, to report errors.
 * @param r FT rule query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
	extern int apol_filename_trans_query_set_regex(const apol_policy_t * p, apol_filename_trans_query_t * r, int is_regex);

/**
 *  Render a filename_transition rule to a string.
 *
 *  @param policy Policy handler, to report errors.
 *  @param rule The rule to render.
 *
 *  @return A newly malloc()'d string representation of the rule, or NULL on
 *  failure; if the call fails, errno will be set. The caller is responsible
 *  for calling free() on the returned string.
 */
	extern char *apol_filename_trans_render(const apol_policy_t * policy, const qpol_filename_trans_t * rule);

#ifdef	__cplusplus
}
#endif

#endif
