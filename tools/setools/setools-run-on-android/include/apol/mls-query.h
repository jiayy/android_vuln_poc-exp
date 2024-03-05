/**
 *  @file
 *  Public interface for querying MLS components, and for
 *  sensitivities and categories within a policy.
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

#ifndef APOL_MLS_QUERY_H
#define APOL_MLS_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "mls_level.h"
#include "mls_range.h"
#include "vector.h"

	typedef struct apol_level_query apol_level_query_t;
	typedef struct apol_cat_query apol_cat_query_t;

/* MLS comparisons function will return one of the following on
   success or -1 on error */
#define APOL_MLS_EQ 0
#define APOL_MLS_DOM 1
#define APOL_MLS_DOMBY 2
#define APOL_MLS_INCOMP 3

/**
 * Determine if two sensitivities are actually the same.  Either level
 * or both could be using a sensitivity's alias, thus straight string
 * comparison is not sufficient.
 *
 * @param p Policy within which to look up MLS information.
 * @param sens1 First sensitivity to compare.
 * @param sens2 Second sensitivity to compare.
 *
 * @return 1 If comparison succeeds, 0 if not; -1 on error.
 */
	extern int apol_mls_sens_compare(const apol_policy_t * p, const char *sens1, const char *sens2);

/**
 * Determine if two categories are actually the same.  Either category
 * or both could be using a category's alias, thus straight string
 * comparison is not sufficient.
 *
 * @param p Policy within which to look up MLS information.
 * @param cat1 First category to compare.
 * @param cat2 Second category to compare.
 *
 * @return 1 If comparison succeeds, 0 if not; -1 on error.
 */
	extern int apol_mls_cats_compare(const apol_policy_t * p, const char *cat1, const char *cat2);

/******************** level queries ********************/

/**
 * Execute a query against all levels within the policy.  The results
 * will only contain levels, not sensitivity aliases.  The returned
 * levels will be unordered.
 *
 * @param p Policy within which to look up levels.
 * @param l Structure containing parameters for query.	If this is
 * NULL then return all levels.
 * @param v Reference to a vector of qpol_level_t.  The vector will be
 * allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon
 * upon error.  Note that the vector may be empty if the policy is
 * not an MLS policy.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_level_get_by_query(const apol_policy_t * p, apol_level_query_t * l, apol_vector_t ** v);

/**
 * Allocate and return a new level query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all levels within the policy.  The caller must call
 * apol_level_query_destroy() upon the return value afterwards.
 *
 * @return An initialized level query structure, or NULL upon error.
 */
	extern apol_level_query_t *apol_level_query_create(void);

/**
 * Deallocate all memory associated with the referenced level query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param l Reference to a level query structure to destroy.
 */
	extern void apol_level_query_destroy(apol_level_query_t ** l);

/**
 * Set a level query to return only levels that match this name.  The
 * name may be either a sensitivity or one of its aliases.  This
 * function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param l Level query to set.
 * @param name Limit query to only sensitivities or aliases with this
 * name, or NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_level_query_set_sens(const apol_policy_t * p, apol_level_query_t * l, const char *name);

/**
 * Set a level query to return only levels contain a particular
 * category.  The name may be either a category or one of its aliases.
 * This function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param l Level query to set.
 * @param name Limit query to levels containing this category or
 * alias, or NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_level_query_set_cat(const apol_policy_t * p, apol_level_query_t * l, const char *name);

/**
 * Set a level query to use regular expression searching for all of
 * its fields.	Strings will be treated as regexes instead of
 * literals.  Matching will occur against the sensitivity name or any
 * of its aliases.
 *
 * @param p Policy handler, to report errors.
 * @param l Level query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
	extern int apol_level_query_set_regex(const apol_policy_t * p, apol_level_query_t * l, int is_regex);

/******************** category queries ********************/

/**
 * Execute a query against all categories within the policy.  The
 * results will only contain categories, not aliases.  The returned
 * categories will be unordered.
 *
 * @param p Policy within which to look up categories.
 * @param c Structure containing parameters for query.	If this is
 * NULL then return all categories.
 * @param v Reference to a vector of qpol_cat_t.  The vector will be
 * allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon
 * upon error.  Note that the vector could be empty if the policy is
 * not an MLS policy.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_cat_get_by_query(const apol_policy_t * p, apol_cat_query_t * c, apol_vector_t ** v);

/**
 * Allocate and return a new category query structure.	All fields are
 * initialized, such that running this blank query results in
 * returning all categories within the policy.	The caller must call
 * apol_cat_query_destroy() upon the return value afterwards.
 *
 * @return An initialized category query structure, or NULL upon
 * error.
 */
	extern apol_cat_query_t *apol_cat_query_create(void);

/**
 * Deallocate all memory associated with the referenced category
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param c Reference to a category query structure to destroy.
 */
	extern void apol_cat_query_destroy(apol_cat_query_t ** c);

/**
 * Set a category query to return only categories that match this
 * name.  The name may be either a category or one of its aliases.
 * This function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param c Category query to set.
 * @param name Limit query to only categories or aliases with this
 * name, or NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_cat_query_set_cat(const apol_policy_t * p, apol_cat_query_t * c, const char *name);

/**
 * Set a category query to use regular expression searching for all of
 * its fields. Strings will be treated as regexes instead of literals.
 * Matching will occur against the category name or any of its
 * aliases.
 *
 * @param p Policy handler, to report errors.
 * @param c Category query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
	extern int apol_cat_query_set_regex(const apol_policy_t * p, apol_cat_query_t * c, int is_regex);

#ifdef	__cplusplus
}
#endif

#endif				       /* APOL_MLS_QUERY_H */
