/**
 *  @file
 *  Public Interface for querying conditional booleans of a policy.
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

#ifndef APOL_BOOL_QUERY_H
#define APOL_BOOL_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include <qpol/policy.h>

	typedef struct apol_bool_query apol_bool_query_t;

/******************** booleans queries ********************/

/**
 * Execute a query against all booleans within the policy.
 *
 * @param p Policy within which to look up booleans.
 * @param b Structure containing parameters for query.	If this is
 * NULL then return all booleans.
 * @param v Reference to a vector of qpol_bool_t.  The vector will be
 * allocated by this function. The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_bool_get_by_query(const apol_policy_t * p, apol_bool_query_t * b, apol_vector_t ** v);

/**
 * Allocate and return a new boolean query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all booleans within the policy.  The caller must call
 * apol_bool_query_destroy() upon the return value afterwards.
 *
 * @return An initialized boolean query structure, or NULL upon error.
 */
	extern apol_bool_query_t *apol_bool_query_create(void);

/**
 * Deallocate all memory associated with the referenced boolean query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param b Reference to a boolean query structure to destroy.
 */
	extern void apol_bool_query_destroy(apol_bool_query_t ** b);

/**
 * Set a boolean query to return only booleans that match this name.
 * This function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param b Boolean query to set.
 * @param name Limit query to only booleans with this name, or NULL to
 * unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_bool_query_set_bool(const apol_policy_t * p, apol_bool_query_t * b, const char *name);

/**
 * Set a boolean query to use regular expression searching for all of
 * its fields.	Strings will be treated as regexes instead of
 * literals.
 *
 * @param p Policy handler, to report errors.
 * @param b Boolean query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
	extern int apol_bool_query_set_regex(const apol_policy_t * p, apol_bool_query_t * b, int is_regex);

#ifdef	__cplusplus
}
#endif

#endif				       /* APOL_BOOL_QUERY_H */
