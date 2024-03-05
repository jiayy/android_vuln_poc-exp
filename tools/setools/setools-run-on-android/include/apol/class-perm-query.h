/**
 * @file
 *
 * Routines to query classes, commons, and permissions of a policy.
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

#ifndef APOL_CLASS_PERM_QUERY_H
#define APOL_CLASS_PERM_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include <qpol/policy.h>

	typedef struct apol_class_query apol_class_query_t;
	typedef struct apol_common_query apol_common_query_t;
	typedef struct apol_perm_query apol_perm_query_t;

/******************** object class queries ********************/

/**
 * Execute a query against all classes within the policy.  The results
 * will only contain object classes, not common classes.
 *
 * @param p Policy within which to look up classes.
 * @param c Structure containing parameters for query.	If this is
 * NULL then return all object classes.
 * @param v Reference to a vector of qpol_class_t.  The vector will be
 * allocated by this function. The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_class_get_by_query(const apol_policy_t * p, apol_class_query_t * c, apol_vector_t ** v);

/**
 * Allocate and return a new class query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all object classes within the policy.  The caller must
 * call apol_class_query_destroy() upon the return value afterwards.
 *
 * @return An initialized class query structure, or NULL upon error.
 */
	extern apol_class_query_t *apol_class_query_create(void);

/**
 * Deallocate all memory associated with the referenced class query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param c Reference to a class query structure to destroy.
 */
	extern void apol_class_query_destroy(apol_class_query_t ** c);

/**
 * Set a class query to return only object classes that match this
 * name.  This function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param c Class query to set.
 * @param name Limit query to only classes with this name, or NULL
 * to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_class_query_set_class(const apol_policy_t * p, apol_class_query_t * c, const char *name);

/**
 * Set a class query to return only object classes that inherit from a
 * particular common class.  Queries will not match classes without
 * commons if this option is set.  This function duplicates the
 * incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param c Class query to set.
 * @param name Limit query to only classes that inherit from this
 * common class, or NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_class_query_set_common(const apol_policy_t * p, apol_class_query_t * c, const char *name);

/**
 * Set a class query to use regular expression searching for all of
 * its fields.	Strings will be treated as regexes instead of
 * literals.
 *
 * @param p Policy handler, to report errors.
 * @param c Class query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
	extern int apol_class_query_set_regex(const apol_policy_t * p, apol_class_query_t * c, int is_regex);

/******************** common class queries ********************/

/**
 * Execute a query against all common classes within the policy.  The
 * results will only contain common classes, not object classes.
 *
 * @param p Policy within which to look up common classes.
 * @param c Structure containing parameters for query.	If this is
 * NULL then return all common classes.
 * @param v Reference to a vector of qpol_common_t.  The vector will
 * be allocated by this function. The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_common_get_by_query(const apol_policy_t * p, apol_common_query_t * c, apol_vector_t ** v);

/**
 * Allocate and return a new common query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all common classes within the policy.  The caller must
 * call apol_common_query_destroy() upon the return value afterwards.
 *
 * @return An initialized common query structure, or NULL upon error.
 */
	extern apol_common_query_t *apol_common_query_create(void);

/**
 * Deallocate all memory associated with the referenced common query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param c Reference to a common query structure to destroy.
 */
	extern void apol_common_query_destroy(apol_common_query_t ** c);

/**
 * Set a common query to return only common classes that match this
 * name.  This function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param c Common query to set.
 * @param name Limit query to only commons with this name, or NULL to
 * unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_common_query_set_common(const apol_policy_t * p, apol_common_query_t * c, const char *name);

/**
 * Set a common query to use regular expression searching for all of
 * its fields.	Strings will be treated as regexes instead of
 * literals.
 *
 * @param p Policy handler, to report errors.
 * @param c Class query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
	extern int apol_common_query_set_regex(const apol_policy_t * p, apol_common_query_t * c, int is_regex);

/******************** permission queries ********************/

/**
 * Execute a query against all permissions (both those declared in
 * classes as well as commons) within the policy.  The results will
 * contain char pointers to permission names.  Thus if the same
 * permission name is declared within multiple classes (e.g.,
 * <tt>file/read</tt> and <tt>socket/read</tt>) then only one instance
 * of <tt>read</tt> is returned.
 *
 * @param p Policy within which to look up permissions.
 * @param pq Structure containing parameters for query.	 If this is
 * NULL then return all permissions.
 * @param v Reference to a vector of character pointers.  The vector
 * will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_perm_get_by_query(const apol_policy_t * p, apol_perm_query_t * pq, apol_vector_t ** v);

/**
 * Allocate and return a new permission query structure.  All fields
 * are initialized, such that running this blank query results in
 * returning all permissions within the policy.	 The caller must call
 * apol_perm_query_destroy() upon the return value afterwards.
 *
 * @return An initialized permission query structure, or NULL upon
 * error.
 */
	extern apol_perm_query_t *apol_perm_query_create(void);

/**
 * Deallocate all memory associated with the referenced permission
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param pq Reference to a permission query structure to destroy.
 */
	extern void apol_perm_query_destroy(apol_perm_query_t ** pq);

/**
 * Set a permission query to return only permissions that match this
 * name.  This function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param pq Permission query to set.
 * @param name Limit query to only permissions with this name, or NULL
 * to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_perm_query_set_perm(const apol_policy_t * p, apol_perm_query_t * pq, const char *name);

/**
 * Set a permission query to use regular expression searching for all
 * of its fields.  Strings will be treated as regexes instead of
 * literals.
 *
 * @param p Policy handler, to report errors.
 * @param pq Permission query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
	extern int apol_perm_query_set_regex(const apol_policy_t * p, apol_perm_query_t * pq, int is_regex);

#ifdef	__cplusplus
}
#endif

#endif
