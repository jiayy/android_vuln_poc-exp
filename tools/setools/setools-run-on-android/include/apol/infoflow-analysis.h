/**
 * @file
 *
 * Routines to perform an information flow analysis, both direct and
 * transitive flows.
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

#ifndef APOL_INFOFLOW_ANALYSIS_H
#define APOL_INFOFLOW_ANALYSIS_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include <qpol/policy.h>

/*
 * Information flows can be either direct (A -> B) or transitive (A ->
 * {stuff} -> B).
 */
#define APOL_INFOFLOW_MODE_DIRECT  0x01
#define APOL_INFOFLOW_MODE_TRANS   0x02

/*
 * All operations are mapped in either an information flow in or an
 * information flow out (using the permission map).  These defines are
 * for the two flow directions plus flows in both or either direction
 * for queries and query results.
 */
#define APOL_INFOFLOW_IN      0x01
#define APOL_INFOFLOW_OUT     0x02
#define APOL_INFOFLOW_BOTH    (APOL_INFOFLOW_IN|APOL_INFOFLOW_OUT)
#define APOL_INFOFLOW_EITHER  0x04

	typedef struct apol_infoflow_graph apol_infoflow_graph_t;
	typedef struct apol_infoflow_analysis apol_infoflow_analysis_t;
	typedef struct apol_infoflow_result apol_infoflow_result_t;
	typedef struct apol_infoflow_step apol_infoflow_step_t;

/**
 * Deallocate all space associated with a particular information flow
 * graph, including the pointer itself.  Afterwards set the pointer to
 * NULL.
 *
 * @param g Reference to an apol_infoflow_graph_t to destroy.
 */
	extern void apol_infoflow_graph_destroy(apol_infoflow_graph_t ** g);

/********** functions to do information flow analysis **********/

/**
 * Execute an information flow analysis against a particular policy.
 * The policy must have had a permission map loaded via
 * apol_policy_open_permmap(), else this analysis will abort
 * immediately.
 *
 * @param p Policy within which to look up allow rules.
 * @param ia A non-NULL structure containing parameters for analysis.
 * @param v Reference to a vector of apol_infoflow_result_t.  The
 * vector will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon
 * error.
 * @param g Reference to the information flow graph constructed for
 * the given infoflow analysis object.  The graph will be allocated by
 * this function; the caller is responsible for calling
 * apol_infoflow_graph_destroy() afterwards.  This will be set to NULL
 * upon error.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_infoflow_analysis_do(const apol_policy_t * p,
					     const apol_infoflow_analysis_t * ia, apol_vector_t ** v, apol_infoflow_graph_t ** g);

/**
 * Execute an information flow analysis against a particular policy
 * and a pre-built information flow graph.  The analysis will keep the
 * same criteria that were used to build the graph, sans differing
 * starting type.
 *
 * @param p Policy within which to look up allow rules.
 * @param g Existing information flow graph to analyze.
 * @param type New string from which to begin analysis.
 * @param v Reference to a vector of apol_infoflow_result_t.  The
 * vector will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_infoflow_analysis_do_more(const apol_policy_t * p, apol_infoflow_graph_t * g, const char *type,
						  apol_vector_t ** v);

/**
 * Prepare an existing transitive infoflow graph to do further
 * searches upon two specific start and end types.  The analysis is by
 * way of a BFS with random restarts; thus each call to
 * apol_infoflow_analysis_trans_further_next() may possibly return
 * additional paths.  This function is needed to prepare the pool of
 * initial states for the search.
 *
 * @param p Policy from which infoflow rules derived.
 * @param g Existing transitive infoflow graph.  If it was already
 * prepared then those values will be first destroyed.
 * @param start_type String from which to begin further analysis.
 * @param end_type String for target infoflow paths.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int apol_infoflow_analysis_trans_further_prepare(const apol_policy_t * p,
								apol_infoflow_graph_t * g, const char *start_type,
								const char *end_type);

/**
 * Find further transitive infoflow paths by way of a random restart.
 * The infoflow graph must be first prepared by first calling
 * apol_infoflow_analysis_trans_further_prepare().  This function will
 * append to vector v any new results it finds.
 *
 * @param p Policy from which infoflow rules derived.
 * @param g Prepared transitive infoflow graph.
 * @param v Pointer to a vector of existing apol_infoflow_result_t
 * pointers.  If this functions finds additional unique results it
 * will append them to this vector.  If the pointer is NULL then this
 * will allocate and return a new vector.  It is the caller's
 * responsibility to call apol_vector_destroy() afterwards.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int apol_infoflow_analysis_trans_further_next(const apol_policy_t * p, apol_infoflow_graph_t * g,
							     apol_vector_t ** v);

/********** functions to create/modify an analysis object **********/

/**
 * Allocate and return a new information analysis structure.  All
 * fields are cleared; one must fill in the details of the analysis
 * before running it.  The caller must call
 * apol_infoflow_analysis_destroy() upon the return value afterwards.
 *
 * @return An initialized information flow analysis structure, or NULL
 * upon error.
 */
	extern apol_infoflow_analysis_t *apol_infoflow_analysis_create(void);

/**
 * Deallocate all memory associated with the referenced information
 * flow analysis, and then set it to NULL.  This function does nothing
 * if the analysis is already NULL.
 *
 * @param ia Reference to an infoflow analysis structure to destroy.
 */
	extern void apol_infoflow_analysis_destroy(apol_infoflow_analysis_t ** ia);

/**
 * Set an information flow analysis mode to be either direct or
 * transitive.  This must be one of the values
 * APOL_INFOFLOW_MODE_DIRECT, or APOL_INFOFLOW_MODE_TRANS.  This
 * function must be called prior to running the analysis.
 *
 * @param p Policy handler, to report errors.
 * @param ia Infoflow analysis to set.
 * @param mode Analysis mode, either direct or transitive.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_infoflow_analysis_set_mode(const apol_policy_t * p, apol_infoflow_analysis_t * ia, unsigned int mode);

/**
 * Set an information flow analysis to search in a specific direction.
 * For direct infoflow analysis this must be one of the values
 * APOL_INFOFLOW_IN, APOL_INFOFLOW_OUT, APOL_INFOFLOW_BOTH, or
 * APOL_INFOFLOW_EITHER; transitive infoflow only permits the first
 * two.  This function must be called prior to running the analysis.
 *
 * @param p Policy handler, to report errors.
 * @param ia Infoflow analysis to set.
 * @param dir Direction to analyze, using one of the defines above.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_infoflow_analysis_set_dir(const apol_policy_t * p, apol_infoflow_analysis_t * ia, unsigned int dir);

/**
 * Set an information flow analysis to begin searching using a given
 * type.  This function must be called prior to running the analysis.
 *
 * @param p Policy handler, to report errors.
 * @param ia Infoflow anlysis to set.
 * @param name Begin searching types with this non-NULL name.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_infoflow_analysis_set_type(const apol_policy_t * p, apol_infoflow_analysis_t * ia, const char *name);

/**
 * Set an information flow analysis to return paths that only go
 * through this intermediate type.  If more than one type is appended
 * to the analysis, every step of a return path will go through at
 * least one of the types.  These intermediate types are ignored when
 * running a direct information flow analysis.
 *
 * @param policy Policy handler, to report errors.
 * @param ia Infoflow analysis to set.
 * @param type Intermediate type which a result must flow through.  If
 * NULL, then clear all existing intermediate types.  (All paths will
 * be returned.)
 * @return 0 on success, negative on error.
 */
	extern int apol_infoflow_analysis_append_intermediate(const apol_policy_t * p, apol_infoflow_analysis_t * ia,
							      const char *type);

/**
 * Set an information flow analysis to return only rules with this
 * object (non-common) class and permission.  If more than one
 * class/perm pair is appended to the query, every rule's class and
 * permissions must be one of those appended.  (I.e., the rule will be
 * a member of the analysis's class/perm pairs.)
 *
 * @param policy Policy handler, to report errors.
 * @param ia Infoflow analysis to set.
 * @param class_name The class to which a result must have access.  If
 * NULL, then accept all class/perm pairs.
 * @param perm_name The permission which a result must have for the
 * given class.  This may be NULL if class_name is also NULL.
 * @return 0 on success, negative on error.
 */
	extern int apol_infoflow_analysis_append_class_perm(const apol_policy_t * p,
							    apol_infoflow_analysis_t * ia, const char *class_name,
							    const char *perm_name);

/**
 * Set an information flow analysis to return only rules with at least
 * one permission whose weight is greater than or equal to the given
 * minimum.  Permission weights are retrieved from the currently
 * loaded permission map.  If the given minimum exceeds
 * APOL_PERMMAP_MAX_WEIGHT it will be clamped to that value.
 *
 * @param policy Policy handler, to report errors.
 * @param ia Infoflow analysis to set.
 * @param min_weight Minimum weight for rules, or negative to accept
 * all rules.
 * @return Always 0.
 */
	extern int apol_infoflow_analysis_set_min_weight(const apol_policy_t * p, apol_infoflow_analysis_t * ia, int min_weight);

/**
 * Set an information flow analysis to return only types matching a
 * regular expression.  Note that the regexp will also match types'
 * aliases.
 *
 * @param p Policy handler, to report errors.
 * @param ia Information flow anlysis to set.
 * @param result Only return types matching this regular expression, or
 * NULL to return all types
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_infoflow_analysis_set_result_regex(const apol_policy_t * p, apol_infoflow_analysis_t * ia,
							   const char *result);

/*************** functions to access infoflow results ***************/

/**
 * Return the direction of an information flow result.  This will be
 * one of APOL_INFOFLOW_IN, APOL_INFOFLOW_OUT, or APOL_INFOFLOW_BOTH.
 *
 * @param result Infoflow result from which to get direction.
 * @return Direction of result or zero on error.
 */
	extern unsigned int apol_infoflow_result_get_dir(const apol_infoflow_result_t * result);

/**
 * Return the start type of an information flow result.  The caller
 * should not free the returned pointer.
 *
 * @param result Infoflow result from which to get start type.
 * @return Pointer to the start type of the infoflow or NULL on error.
 */
	extern const qpol_type_t *apol_infoflow_result_get_start_type(const apol_infoflow_result_t * result);

/**
 * Return the end type of an information flow result.  The caller
 * should not free the returned pointer.
 *
 * @param result Infoflow result from which to get end type.
 * @return Pointer to the end type of the infoflow or NULL on error.
 */
	extern const qpol_type_t *apol_infoflow_result_get_end_type(const apol_infoflow_result_t * result);

/**
 * Return the length of an information flow result.  This represents
 * how easily information flows from the start to end type, where
 * lower numbers are easier than higher numbers.  This is dependent
 * upon the weights assigned in the currently loaded permission map.
 *
 * @param result Infoflow result from which to get length.
 * @return Length of result or zero on error.
 */
	extern unsigned int apol_infoflow_result_get_length(const apol_infoflow_result_t * result);

/**
 * Return the vector of infoflow steps for a particular information
 * flow result.  This is a vector of apol_infoflow_step_t pointers.
 * The caller <b>should not</b> call apol_vector_destroy() upon the
 * returned vector.  Note that for a direct infoflow analysis this
 * vector will consist of exactly one step; for transitive analysis
 * the vector will have multiple steps.
 *
 * @param result Infoflow result from which to get steps.
 *
 * @return Pointer to a vector of steps found between the result's
 * start and end types or NULL on error.
 */
	extern const apol_vector_t *apol_infoflow_result_get_steps(const apol_infoflow_result_t * result);

/**
 * Return the starting type for an information flow step.  The caller
 * should not free the returned pointer.
 *
 * @param step Infoflow step from which to get start type.
 * @return Pointer to the start type for this infoflow step or NULL on error.
 */
	extern const qpol_type_t *apol_infoflow_step_get_start_type(const apol_infoflow_step_t * step);

/**
 * Return the ending type for an information flow step.  The caller
 * should not free the returned pointer.
 *
 * @param step Infoflow step from which to get end type.
 * @return Pointer to the start type for this infoflow step or NULL on error.
 */
	extern const qpol_type_t *apol_infoflow_step_get_end_type(const apol_infoflow_step_t * step);

/**
 * Return the weight of an information flow step.  For a direct
 * infoflow analysis the weight is zero.  For a transitive
 * analysis this is an integer value that quantatizes the amount of
 * information that could flow between the start and end types; it is
 * based upon the currently opened permission map.  It will be a value
 * between APOL_PERMMAP_MIN_WEIGHT and APOL_PERMMAP_MAX_WEIGHT,
 * inclusive.
 *
 * @param step Infoflow step from which to get weight.
 * @return Weight of step or < 0 on error.
 */
	extern int apol_infoflow_step_get_weight(const apol_infoflow_step_t * step);

/**
 * Return the vector of access rules for a particular information
 * step.  This is a vector of qpol_avrule_t pointers.  The caller
 * <b>should not</b> call apol_vector_destroy() upon the returned
 * vector.
 *
 * @param step Infoflow flow step from which to get rules.
 *
 * @return Pointer to a vector of rules relative to the policy originally
 * used to generate the results or NULL on error.
 */
	extern const apol_vector_t *apol_infoflow_step_get_rules(const apol_infoflow_step_t * step);

#ifdef	__cplusplus
}
#endif

#endif
