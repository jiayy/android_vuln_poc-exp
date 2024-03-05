/**
 *  @file
 *  Public Interface for querying users of a policy.
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

#ifndef APOL_USER_QUERY_H
#define APOL_USER_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include "mls-query.h"
#include <qpol/policy.h>

	typedef struct apol_user_query apol_user_query_t;

/******************** user queries ********************/

/**
 * Execute a query against all users within the policy.
 *
 * @param p Policy within which to look up users.
 * @param u Structure containing parameters for query.	If this is
 * NULL then return all users.
 * @param v Reference to a vector of qpol_user_t.  The vector will be
 * allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_user_get_by_query(const apol_policy_t * p, apol_user_query_t * u, apol_vector_t ** v);

/**
 * Allocate and return a new user query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all users within the policy.  The caller must call
 * apol_user_query_destroy() upon the return value afterwards.
 *
 * @return An initialized user query structure, or NULL upon error.
 */
	extern apol_user_query_t *apol_user_query_create(void);

/**
 * Deallocate all memory associated with the referenced user query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param u Reference to a user query structure to destroy.
 */
	extern void apol_user_query_destroy(apol_user_query_t ** u);

/**
 * Set a user query to return only users that match this name.	This
 * function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param u User query to set.
 * @param name Limit query to only users this name, or NULL to unset
 * this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_user_query_set_user(const apol_policy_t * p, apol_user_query_t * u, const char *name);

/**
 * Set a user query to return only users containing this role.	This
 * function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param u User query to set.
 * @param role Limit query to only users with this role, or NULL to
 * unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_user_query_set_role(const apol_policy_t * p, apol_user_query_t * u, const char *role);

/**
 * Set a user query to return only users containing this default
 * level.  This function takes ownership of the level, such that the
 * caller must not modify nor destroy it afterwards.
 *
 * @param p Policy handler, to report errors.
 * @param u User query to which set.
 * @param level Limit query to only users with this level as their
 * default, or NULL to unset this field.
 *
 * @return Always returns 0.
 */
	extern int apol_user_query_set_default_level(const apol_policy_t * p, apol_user_query_t * u, apol_mls_level_t * level);

/**
 * Set a user query to return only users matching a MLS range.	This
 * function takes ownership of the range, such that the caller must
 * not modify nor destroy it afterwards.
 *
 * @param p Policy handler, to report errors.
 * @param u User query to set.
 * @param range Limit query to only users matching this range, or NULL
 * to unset this field.
 * @param range_match Specifies how to match a user to a range.	 This
 * must be one of APOL_QUERY_SUB, APOL_QUERY_SUPER, or
 * APOL_QUERY_EXACT.  This parameter is ignored if range is NULL.
 *
 * @return Always returns 0.
 */
	extern int apol_user_query_set_range(const apol_policy_t * p, apol_user_query_t * u, apol_mls_range_t * range,
					     unsigned int range_match);

/**
 * Set a user query to use regular expression searching for all of its
 * fields.  Strings will be treated as regexes instead of literals.
 *
 * @param p Policy handler, to report errors.
 * @param u User query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
	extern int apol_user_query_set_regex(const apol_policy_t * p, apol_user_query_t * u, int is_regex);

#ifdef	__cplusplus
}
#endif

#endif				       /* APOL_USER_QUERY_H */
