/**
 *  @file
 *  Public Interface for querying initial SIDs of a policy.
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

#ifndef APOL_ISID_QUERY_H
#define APOL_ISID_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include "context-query.h"
#include <qpol/policy.h>

	typedef struct apol_isid_query apol_isid_query_t;

/******************** isid queries ********************/

/**
 * Execute a query against all initial SIDs within the policy.	The
 * returned isids will be unordered.
 *
 * @param p Policy within which to look up initial SIDs.
 * @param i Structure containing parameters for query.	If this is
 * NULL then return all isids.
 * @param v Reference to a vector of qpol_isid_t.  The vector will be
 * allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_isid_get_by_query(const apol_policy_t * p, const apol_isid_query_t * i, apol_vector_t ** v);

/**
 * Allocate and return a new isid query structure. All fields are
 * initialized, such that running this blank query results in
 * returning all initial SIDs within the policy.  The caller must call
 * apol_isid_query_destroy() upon the return value afterwards.
 *
 * @return An initialized isid query structure, or NULL upon error.
 */
	extern apol_isid_query_t *apol_isid_query_create(void);

/**
 * Deallocate all memory associated with the referenced isid query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param i Reference to an isid query structure to destroy.
 */
	extern void apol_isid_query_destroy(apol_isid_query_t ** i);

/**
 * Set an isid query to return only initial SIDs with this name.
 *
 * @param p Policy handler, to report errors.
 * @param i isid query to set.
 * @param name Limit query to only initial SIDs with this name, or
 * NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_isid_query_set_name(const apol_policy_t * p, apol_isid_query_t * i, const char *name);

/**
 * Set an isid query to return only initial SIDs matching a context.
 * This function takes ownership of the context, such that the caller
 * must not modify nor destroy it afterwards.
 *
 * @param p Policy handler, to report errors.
 * @param i isid query to set.
 * @param context Limit query to only initial SIDs matching this
 * context, or NULL to unset this field.
 * @param range_match Specifies how to match the MLS range within the
 * context.  This must be one of APOL_QUERY_SUB, APOL_QUERY_SUPER, or
 * APOL_QUERY_EXACT.  This parameter is ignored if context is NULL.
 *
 * @return Always returns 0.
 */
	extern int apol_isid_query_set_context(const apol_policy_t * p,
					       apol_isid_query_t * i, apol_context_t * context, unsigned int range_match);

#ifdef	__cplusplus
}
#endif

#endif				       /* APOL_ISID_QUERY_H */
