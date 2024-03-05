/**
 * @file
 *
 * Routines to query types and attributes of a policy.
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

#ifndef APOL_TYPE_QUERY_H
#define APOL_TYPE_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include <qpol/policy.h>

	typedef struct apol_type_query apol_type_query_t;
	typedef struct apol_attr_query apol_attr_query_t;

/******************** type queries ********************/

/**
 * Execute a query against all types within the policy.	 The results
 * will only contain types, not aliases nor attributes.
 *
 * @param p Policy within which to look up types.
 * @param t Structure containing parameters for query.	If this is
 * NULL then return all types.
 * @param v Reference to a vector of qpol_type_t.  The vector will be
 * allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_type_get_by_query(const apol_policy_t * p, apol_type_query_t * t, apol_vector_t ** v);

/**
 * Allocate and return a new type query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all types within the policy.  The caller must call
 * apol_type_query_destroy() upon the return value afterwards.
 *
 * @return An initialized type query structure, or NULL upon error.
 */
	extern apol_type_query_t *apol_type_query_create(void);

/**
 * Deallocate all memory associated with the referenced type query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param t Reference to a type query structure to destroy.
 */
	extern void apol_type_query_destroy(apol_type_query_t ** t);

/**
 * Set a type query to return only types that match this name.	The
 * name may be either a type or one of its aliases.  This function
 * duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param t Type query to set.
 * @param name Limit query to only types or aliases with this name, or
 * NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_type_query_set_type(const apol_policy_t * p, apol_type_query_t * t, const char *name);

/**
 * Set a type query to use regular expression searching for all of its
 * fields.  Strings will be treated as regexes instead of literals.
 * Matching will occur against the type name or any of its aliases.
 *
 * @param p Policy handler, to report errors.
 * @param t Type query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
	extern int apol_type_query_set_regex(const apol_policy_t * p, apol_type_query_t * t, int is_regex);

/******************** attribute queries ********************/

/**
 * Execute a query against all attributes within the policy.  The
 * results will only contain attributes, not types nor aliases.
 *
 * @param p Policy within which to look up attributes.
 * @param a Structure containing parameters for query.	If this is
 * NULL then return all attributes.
 * @param v Reference to a vector of qpol_type_t.  The vector will be
 * allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_attr_get_by_query(const apol_policy_t * p, apol_attr_query_t * a, apol_vector_t ** v);

/**
 * Allocate and return a new attribute query structure.	 All fields
 * are initialized, such that running this blank query results in
 * returning all attributes within the policy.	The caller must call
 * apol_attr_query_destroy() upon the return value afterwards.
 *
 * @return An initialized attribute query structure, or NULL upon error.
 */
	extern apol_attr_query_t *apol_attr_query_create(void);

/**
 * Deallocate all memory associated with the referenced attribute
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param a Reference to an attribute query structure to destroy.
 */
	extern void apol_attr_query_destroy(apol_attr_query_t ** a);

/**
 * Set an attribute query to return only attributes that match this
 * name.  This function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param a Attribute query to set.
 * @param name Limit query to only attributes with this name, or NULL
 * to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_attr_query_set_attr(const apol_policy_t * p, apol_attr_query_t * a, const char *name);

/**
 * Set an attribute query to use regular expression searching for all
 * of its fields.  Strings will be treated as regexes instead of
 * literals.
 *
 * @param p Policy handler, to report errors.
 * @param a Attribute query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
	extern int apol_attr_query_set_regex(const apol_policy_t * p, apol_attr_query_t * a, int is_regex);

#ifdef	__cplusplus
}
#endif

#endif
