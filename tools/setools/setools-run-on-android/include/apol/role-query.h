/**
 *  @file
 *  Public Interface for querying roles of a policy.
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

#ifndef APOL_ROLE_QUERY_H
#define APOL_ROLE_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include <qpol/policy.h>

	typedef struct apol_role_query apol_role_query_t;

/******************** role queries ********************/

/**
 * Execute a query against all roles within the policy.
 *
 * @param p Policy within which to look up roles.
 * @param r Structure containing parameters for query.	If this is
 * NULL then return all roles.
 * @param v Reference to a vector of qpol_role_t.  The vector will be
 * allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_role_get_by_query(const apol_policy_t * p, apol_role_query_t * r, apol_vector_t ** v);

/**
 * Allocate and return a new role query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all roles within the policy.  The caller must call
 * apol_role_query_destroy() upon the return value afterwards.
 *
 * @return An initialized role query structure, or NULL upon error.
 */
	extern apol_role_query_t *apol_role_query_create(void);

/**
 * Deallocate all memory associated with the referenced role query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param r Reference to a role query structure to destroy.
 */
	extern void apol_role_query_destroy(apol_role_query_t ** r);

/**
 * Set a role query to return only roles that match this name.	This
 * function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param r Role query to set.
 * @param name Limit query to only roles with this name, or NULL to
 * unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_role_query_set_role(const apol_policy_t * p, apol_role_query_t * r, const char *name);

/**
 * Set a role query to return only roles containing this type or one
 * of its aliases.  This function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param r Role query to set.
 * @param name Limit query to only roles with this type, or NULL to
 * unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_role_query_set_type(const apol_policy_t * p, apol_role_query_t * r, const char *name);

/**
 * Set a role query to use regular expression searching for all of its
 * fields.  Strings will be treated as regexes instead of literals.
 *
 * @param p Policy handler, to report errors.
 * @param r Role query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
	extern int apol_role_query_set_regex(const apol_policy_t * p, apol_role_query_t * r, int is_regex);

/**
 * See if the role passed in includes the type that is the
 * second parameter.
 * @param p Policy handler, to report errors.
 * @param r Role to check if type is included in it.
 * @param t Type that is checked against all types that are in role
 * @return 1 if the type is included in the role, 0 if it's not, < 0 on error
*/
	extern int apol_role_has_type(const apol_policy_t * p, const qpol_role_t * r, const qpol_type_t * t);

#ifdef	__cplusplus
}
#endif

#endif				       /* APOL_ROLE_QUERY_H */
