/**
 * @file
 *
 * Routines to perform a two-types relationship analysis.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2003-2007 Tresys Technology, LLC
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

#ifndef APOL_TYPES_RELATION_ANALYSIS_H
#define APOL_TYPES_RELATION_ANALYSIS_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include <qpol/policy.h>

/* Specify a which types relationship analysis/analyses to run using
 * these bit values.
 */
#define APOL_TYPES_RELATION_COMMON_ATTRIBS 0x0001
#define APOL_TYPES_RELATION_COMMON_ROLES 0x0002
#define APOL_TYPES_RELATION_COMMON_USERS 0x0004
#define APOL_TYPES_RELATION_SIMILAR_ACCESS 0x0010
#define APOL_TYPES_RELATION_DISSIMILAR_ACCESS 0x0020
#define APOL_TYPES_RELATION_ALLOW_RULES 0x0100
#define APOL_TYPES_RELATION_TYPE_RULES 0x0200
#define APOL_TYPES_RELATION_DOMAIN_TRANS_AB 0x0400
#define APOL_TYPES_RELATION_DOMAIN_TRANS_BA 0x0800
#define APOL_TYPES_RELATION_DIRECT_FLOW 0x1000
#define APOL_TYPES_RELATION_TRANS_FLOW_AB 0x4000
#define APOL_TYPES_RELATION_TRANS_FLOW_BA 0x8000

	typedef struct apol_types_relation_analysis apol_types_relation_analysis_t;
	typedef struct apol_types_relation_result apol_types_relation_result_t;
	typedef struct apol_types_relation_access apol_types_relation_access_t;

/********** functions to do types relation analysis **********/

/**
 * Execute a two types relationship analysis against a particular
 * policy.
 *
 * @param p Policy within which to look up relationships.
 * @param tr A non-NULL structure containing parameters for analysis.
 * @param r Reference to a apol_types_relation_result_t.  The object
 * will be allocated by this function.  The caller must call
 * apol_types_relation_result_destroy() afterwards.  This will be set
 * to NULL upon no results or upon error.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_types_relation_analysis_do(apol_policy_t * p,
						   const apol_types_relation_analysis_t * tr, apol_types_relation_result_t ** r);

/**
 * Allocate and return a new two types relationship analysis
 * structure.  All fields are cleared; one must fill in the details of
 * the analysis before running it.  The caller must call
 * apol_types_relation_analysis_destroy() upon the return value
 * afterwards.
 *
 * @return An initialized two types relationship analysis structure, or
 * NULL upon error.
 */
	extern apol_types_relation_analysis_t *apol_types_relation_analysis_create(void);

/**
 * Deallocate all memory associated with the referenced types relation
 * analysis, and then set it to NULL.  This function does nothing if
 * the analysis is already NULL.
 *
 * @param tr Reference to a types relation analysis structure to
 * destroy.
 */
	extern void apol_types_relation_analysis_destroy(apol_types_relation_analysis_t ** tr);

/**
 * Set a types relation analysis to begin analysis from this first
 * type.  This function must be called prior to running the analysis.
 *
 * @param p Policy handler, to report errors.
 * @param tr Types relation analysis to set.
 * @param name Perform analysis with this non-NULL name.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_types_relation_analysis_set_first_type(const apol_policy_t * p, apol_types_relation_analysis_t * tr,
							       const char *name);

/**
 * Set a types relation analysis to begin analysis from this other
 * type.  This function must be called prior to running the analysis.
 *
 * @param p Policy handler, to report errors.
 * @param tr Types relation analysis to set.
 * @param name Perform analysis with this other non-NULL name.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_types_relation_analysis_set_other_type(const apol_policy_t * p, apol_types_relation_analysis_t * tr,
							       const char *name);

/**
 * Set a types relation analysis to run the specified
 * analysis/analyses.  This is a bitmap; use the defines
 * APOL_TYPES_RELATION_COMMON_ATTRIBUTES etc. to specify which one(s)
 * to run.
 *
 * @param p Policy handler, to report errors.
 * @param tr Types relation analysis to set.
 * @param analyses Bitmap to indicate which analyses to run, or 0 to
 * run them all.
 *
 * @return Always 0.
 */
	extern int apol_types_relation_analysis_set_analyses(const apol_policy_t * p, apol_types_relation_analysis_t * tr,
							     unsigned int analyses);

/*************** functions to access types relation results ***************/

/**
 * Deallocate all memory associated with a types relation analysis
 * result, including the pointer itself.  This function does nothing
 * if the result is already NULL.
 *
 * @param result Reference to a types relation result structure to
 * destroy.
 */
	extern void apol_types_relation_result_destroy(apol_types_relation_result_t ** result);

/**
 * Return the vector of attributes common to the two types.  This is a
 * vector of qpol_type_t pointers.  The caller <b>should not</b> call
 * apol_vector_destroy() upon the returned vector.  If the user did
 * not request this analysis then the return value will be NULL.
 *
 * @param result Types relation result from which to get common
 * attributes.
 *
 * @return Vector of common attributes, or NULL if analysis was not
 * run.
 */
	extern const apol_vector_t *apol_types_relation_result_get_attributes(const apol_types_relation_result_t * result);

/**
 * Return the vector of roles common to the two types.  This is a
 * vector of qpol_role_t pointers.  The caller <b>should not</b> call
 * apol_vector_destroy() upon the returned vector.  If the user did
 * not request this analysis then the return value will be NULL.
 *
 * @param result Types relation result from which to get common roles.
 *
 * @return Vector of common roles, or NULL if analysis was not run.
 */
	extern const apol_vector_t *apol_types_relation_result_get_roles(const apol_types_relation_result_t * result);

/**
 * Return the vector of users common to the two types.  This is a
 * vector of qpol_user_t pointers.  The caller <b>should not</b> call
 * apol_vector_destroy() upon the returned vector.  If the user did
 * not request this analysis then the return value will be NULL.
 *
 * @param result Types relation result from which to get common users.
 *
 * @return Vector of common users, or NULL if analysis was not run.
 */
	extern const apol_vector_t *apol_types_relation_result_get_users(const apol_types_relation_result_t * result);

/**
 * Return the vector of accesses similar to the two types.  This is a
 * vector of apol_types_relation_access_t pointers.  The vector will
 * contain only the rules that the first type had.  Call
 * apol_types_relation_result_get_similar_other() to get the
 * complementary vector (i.e., both vectors will have the same types).
 * The caller <b>should not</b> call apol_vector_destroy() upon the
 * returned vector.  If the user did not request this analysis then
 * the return value will be NULL.
 *
 * @param result Types relation result from which to get similar accesses.
 *
 * @return Vector of similar accesses, or NULL if analysis was not run.
 */
	extern const apol_vector_t *apol_types_relation_result_get_similar_first(const apol_types_relation_result_t * result);

/**
 * Return the vector of accesses similar to the two types.  This is a
 * vector of apol_types_relation_access_t pointers.  The vector will
 * contain only the rules that the other type had.  Call
 * apol_types_relation_result_get_similar_first() to get the
 * complementary vector (i.e., both vectors will have the same types).
 * The caller <b>should not</b> call apol_vector_destroy() upon the
 * returned vector.  If the user did not request this analysis then
 * the return value will be NULL.
 *
 * @param result Types relation result from which to get similar accesses.
 *
 * @return Vector of similar accesses, or NULL if analysis was not run.
 */
	extern const apol_vector_t *apol_types_relation_result_get_similar_other(const apol_types_relation_result_t * result);

/**
 * Return the vector of accesses dissimilar for the first type (i.e.,
 * types that the first type reaches that the other type does not).
 * This is a vector of apol_types_relation_access_t pointers.  The
 * caller <b>should not</b> call apol_vector_destroy() upon the
 * returned vector.  If the user did not request this analysis then
 * the return value will be NULL.
 *
 * @param result Types relation result from which to get dissimilar
 * accesses.
 *
 * @return Vector of dissimilar accesses, or NULL if analysis was not
 * run.
 */
	extern const apol_vector_t *apol_types_relation_result_get_dissimilar_first(const apol_types_relation_result_t * result);

/**
 * Return the vector of accesses dissimilar for the other type (i.e.,
 * types that the other type reaches that the first type does not).
 * This is a vector of apol_types_relation_access_t pointers.  The
 * caller <b>should not</b> call apol_vector_destroy() upon the
 * returned vector.  If the user did not request this analysis then
 * the return value will be NULL.
 *
 * @param result Types relation result from which to get dissimilar
 * accesses.
 *
 * @return Vector of dissimilar accesses, or NULL if analysis was not
 * run.
 */
	extern const apol_vector_t *apol_types_relation_result_get_dissimilar_other(const apol_types_relation_result_t * result);

/**
 * Return the vector of allow rules involving both types (allow one
 * type to the other).  This is a vector of qpol_avrule_t pointers.
 * The caller <b>should not</b> call apol_vector_destroy() upon the
 * returned vector.  If the user did not request this analysis then
 * the return value will be NULL.
 *
 * @param result Types relation result from which to get rules.
 *
 * @return Vector of allow rules, or NULL if analysis was not run.
 */
	extern const apol_vector_t *apol_types_relation_result_get_allowrules(const apol_types_relation_result_t * result);

/**
 * Return the vector of type transition / type change rules involving
 * both types.  This is a vector of qpol_terule_t pointers.  The
 * caller <b>should not</b> call apol_vector_destroy() upon the
 * returned vector.  If the user did not request this analysis then
 * the return value will be NULL.
 *
 * @param result Types relation result from which to get rules.
 *
 * @return Vector of type enforcement rules, or NULL if analysis was
 * not run.
 */
	extern const apol_vector_t *apol_types_relation_result_get_typerules(const apol_types_relation_result_t * result);

/**
 * Return the vector of apol_infoflow_result_t pointers corresponding
 * to a direct information flow analysis between both types.  The
 * caller <b>should not</b> call apol_vector_destroy() upon the
 * returned vector.  If the user did not request this analysis then
 * the return value will be NULL.
 *
 * @param result Types relation result from which to get information
 * flows.
 *
 * @return Vector of infoflow results, or NULL if analysis was not
 * run.
 */
	extern const apol_vector_t *apol_types_relation_result_get_directflows(const apol_types_relation_result_t * result);

/**
 * Return the vector of apol_infoflow_result_t pointers corresponding
 * to a transitive information flow analysis between the first type to
 * the other.  The caller <b>should not</b> call apol_vector_destroy()
 * upon the returned vector.  If the user did not request this
 * analysis then the return value will be NULL.
 *
 * @param result Types relation result from which to get information
 * flows.
 *
 * @return Vector of infoflow results, or NULL if analysis was not
 * run.
 */
	extern const apol_vector_t *apol_types_relation_result_get_transflowsAB(const apol_types_relation_result_t * result);

/**
 * Return the vector of apol_infoflow_result_t pointers corresponding
 * to a transitive information flow analysis between the other type to
 * the first.  The caller <b>should not</b> call apol_vector_destroy()
 * upon the returned vector.  If the user did not request this
 * analysis then the return value will be NULL.
 *
 * @param result Types relation result from which to get information
 * flows.
 *
 * @return Vector of infoflow results, or NULL if analysis was not
 * run.
 */
	extern const apol_vector_t *apol_types_relation_result_get_transflowsBA(const apol_types_relation_result_t * result);

/**
 * Return the vector of apol_domain_trans_result_t pointers
 * corresponding to a domain transition analysis between the first
 * type to the other.  The caller <b>should not</b> call
 * apol_vector_destroy() upon the returned vector.  If the user did
 * not request this analysis then the return value will be NULL.
 *
 * @param result Types relation result from which to get domain
 * transitions.
 *
 * @return Vector of domain transition results, or NULL if analysis
 * was not run.
 */
	extern const apol_vector_t *apol_types_relation_result_get_domainsAB(const apol_types_relation_result_t * result);

/**
 * Return the vector of apol_domain_trans_result_t pointers
 * corresponding to a domain transition analysis between the other
 * type to the first.  The caller <b>should not</b> call
 * apol_vector_destroy() upon the returned vector.  If the user did
 * not request this analysis then the return value will be NULL.
 *
 * @param result Types relation result from which to get domain
 * transitions.
 *
 * @return Vector of domain transition results, or NULL if analysis
 * was not run.
 */
	extern const apol_vector_t *apol_types_relation_result_get_domainsBA(const apol_types_relation_result_t * result);

/**
 * Given a types relation access node, return the type stored within.
 *
 * @param a Types relation access node.
 *
 * @return Pointer to the type stored within.
 */
	extern const qpol_type_t *apol_types_relation_access_get_type(const apol_types_relation_access_t * a);

/**
 * Given a types relation access node, return the vector of
 * qpol_avrule_t pointers stored within.
 *
 * @param a Types relation access node.
 *
 * @return Pointer to the vector of rules.  The caller <b>must not</b>
 * destroy this vector.
 */
	extern const apol_vector_t *apol_types_relation_access_get_rules(const apol_types_relation_access_t * a);

#ifdef	__cplusplus
}
#endif

#endif
