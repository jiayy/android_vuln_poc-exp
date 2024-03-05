/**
 * @file
 *
 * Routines to query constraint and validatetrans statements in a policy.
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

#ifndef APOL_CONSTRAINT_QUERY_H
#define APOL_CONSTRAINT_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"

	typedef struct apol_constraint_query apol_constraint_query_t;
	typedef struct apol_validatetrans_query apol_validatetrans_query_t;

/******************** constraint queries ********************/

/**
 * Execute a query against all constraints within the policy.
 *
 * @param p Policy within which to look up constraints.
 * @param c Structure containing parameters for query.  If this is
 * NULL then return all constraints.
 * @param v Reference to a vector of qpol_constraint_t.  The vector
 * will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_constraint_get_by_query(const apol_policy_t * p, apol_constraint_query_t * c, apol_vector_t ** v);

/**
 * Allocate and return a new constraint query structure.  All fields
 * are initialized, such that running this blank query results in
 * returning all constraints within the policy.  The caller must call
 * apol_constraint_query_destroy() upon the return value afterwards.
 *
 * @return An initialized constraint query structure, or NULL upon
 * error.
 */
	extern apol_constraint_query_t *apol_constraint_query_create(void);

/**
 * Deallocate all memory associated with the referenced constraint
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param c Reference to a constraint query structure to destroy.
 */
	extern void apol_constraint_query_destroy(apol_constraint_query_t ** c);

/**
 * Set a constraint query to return only constraints that use object
 * classes that match this name.  This function duplicates the
 * incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param c Constraint query to set.
 * @param name Limit query to only classes with this name, or NULL
 * to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_constraint_query_set_class(const apol_policy_t * p, apol_constraint_query_t * c, const char *name);

/**
 * Set a constraint query to return only constraints that employ
 * permissions that match this name.  This function duplicates the
 * incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param c Constraint query to set.
 * @param name Limit query to only permissions with this name, or NULL
 * to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_constraint_query_set_perm(const apol_policy_t * p, apol_constraint_query_t * c, const char *name);

/**
 * Set a constraint query to use regular expression searching for all
 * of its fields. Strings will be treated as regexes instead of
 * literals.
 *
 * @param p Policy handler, to report errors.
 * @param c Constraint query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
	extern int apol_constraint_query_set_regex(const apol_policy_t * p, apol_constraint_query_t * c, int is_regex);

/******************** validatetrans queries ********************/

/**
 * Execute a query against all validatetrans statements within the
 * policy.
 *
 * @param p Policy within which to look up validatetrans statements.
 * @param vr Structure containing parameters for query.  If this is
 * NULL then return all validatetrans statements.
 * @param v Reference to a vector of qpol_validatetrans_t.  The vector
 * will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_validatetrans_get_by_query(const apol_policy_t * p, apol_validatetrans_query_t * vt, apol_vector_t ** v);

/**
 * Allocate and return a new validatetrans query structure.  All
 * fields are initialized, such that running this blank query results
 * in returning all validatetrans within the policy.  The caller must
 * call apol_validatetrans_query_destroy() upon the return value
 * afterwards.
 *
 * @return An initialized validatetrans query structure, or NULL upon
 * error.
 */
	extern apol_validatetrans_query_t *apol_validatetrans_query_create(void);

/**
 * Deallocate all memory associated with the referenced validatetrans
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param vt Reference to a validatetrans query structure to destroy.
 */
	extern void apol_validatetrans_query_destroy(apol_validatetrans_query_t ** vt);

/**
 * Set a validatetrans query to return only validatetrans that use
 * object classes that match this name.  This function duplicates the
 * incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param vt Validatetrans query to set.
 * @param name Limit query to only classes with this name, or NULL
 * to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_validatetrans_query_set_class(const apol_policy_t * p, apol_validatetrans_query_t * vt, const char *name);

/**
 * Set a validatetrans query to use regular expression searching for
 * all of its fields.  Strings will be treated as regexes instead of
 * literals.
 *
 * @param p Policy handler, to report errors.
 * @param vt Validatetrans query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
	extern int apol_validatetrans_query_set_regex(const apol_policy_t * p, apol_validatetrans_query_t * vt, int is_regex);

#ifdef	__cplusplus
}
#endif

#endif
