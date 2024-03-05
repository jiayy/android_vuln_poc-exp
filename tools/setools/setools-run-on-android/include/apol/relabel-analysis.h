/**
 * @file
 *
 * Routines to perform a direct relabelling analysis.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2005-2007 Tresys Technology, LLC
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

#ifndef APOL_RELABEL_ANALYSIS_H
#define APOL_RELABEL_ANALYSIS_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include <qpol/policy.h>

/* defines for direction flag */
#define APOL_RELABEL_DIR_TO      0x01
#define APOL_RELABEL_DIR_FROM    0x02
#define APOL_RELABEL_DIR_BOTH    (APOL_RELABEL_DIR_TO|APOL_RELABEL_DIR_FROM)
#define APOL_RELABEL_DIR_SUBJECT 0x04

	typedef struct apol_relabel_analysis apol_relabel_analysis_t;
	typedef struct apol_relabel_result apol_relabel_result_t;
	typedef struct apol_relabel_result_pair apol_relabel_result_pair_t;

/******************** functions to do relabel analysis ********************/

/**
 * Execute a relabel analysis against a particular policy.
 *
 * @param p Policy within which to look up allow rules.
 * @param r A non-NULL structure containing parameters for analysis.
 * @param v Reference to a vector of apol_relabel_result_t.  The
 * vector will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_relabel_analysis_do(const apol_policy_t * p, apol_relabel_analysis_t * r, apol_vector_t ** v);

/**
 * Allocate and return a new relabel analysis structure.  All fields
 * are cleared; one must fill in the details of the analysis before
 * running it.  The caller must call apol_relabel_analysis_destroy()
 * upon the return value afterwards.
 *
 * @return An initialized relabel analysis structure, or NULL upon
 * error.
 */
	extern apol_relabel_analysis_t *apol_relabel_analysis_create(void);

/**
 * Deallocate all memory associated with the referenced relabel
 * analysis, and then set it to NULL.  This function does nothing if
 * the analysis is already NULL.
 *
 * @param r Reference to a relabel analysis structure to destroy.
 */
	extern void apol_relabel_analysis_destroy(apol_relabel_analysis_t ** r);

/**
 * Set a relabel analysis to search in a specific direction.  This
 * function must be called prior to running the analysis.
 *
 * @param p Policy handler, to report errors.
 * @param r Relabel analysis to set.
 * @param dir Direction to analyze, one of the APOL_RELABEL_DIR_TO,
 * APOL_RELABEL_DIR_FROM, APOL_RELABEL_DIR_BOTH, or
 * APOL_RELABEL_DIR_SUBJECT.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_relabel_analysis_set_dir(const apol_policy_t * p, apol_relabel_analysis_t * r, unsigned int dir);

/**
 * Set a relabel analysis to begin searching using a given type.  This
 * function must be called prior to running the analysis.
 *
 * @param p Policy handler, to report errors.
 * @param r Relabel anlysis to set.
 * @param name Begin searching types with this non-NULL name.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_relabel_analysis_set_type(const apol_policy_t * p, apol_relabel_analysis_t * r, const char *name);

/**
 * Set a relabel analysis to return rules with this object
 * (non-common) class.  If more than one class is appended to the
 * query, the rule's class must be one of those appended.  (I.e., the
 * rule's class must be a member of the analysis's classes.)  Pass a
 * NULL to clear all classes.
 *
 * @param p Policy handler, to report errors.
 * @param r Relabel analysis to set.
 * @param class Name of object class to add to search set, or NULL to
 * clear all classes.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_relabel_analysis_append_class(const apol_policy_t * p, apol_relabel_analysis_t * r, const char *obj_class);

/**
 * Set a relabel analysis to return rules with this subject as their
 * source type.  If more than one subject is appended to the query,
 * the rule's source must be one of those appended.  (I.e., the rule's
 * source must be a member of the analysis's subject.)  Pass a NULL to
 * clear all types.  Note that these subjects are ignored when doing
 * subject relabel analysis.
 *
 * @param p Policy handler, to report errors.
 * @param r Relabel analysis to set.
 * @param subject Name of type to add to search set, or NULL to clear
 * all subjects.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_relabel_analysis_append_subject(const apol_policy_t * p, apol_relabel_analysis_t * r, const char *subject);

/**
 * Set a relabel analysis to return only types matching a regular
 * expression.  Note that the regexp will also match types' aliases.
 *
 * @param p Policy handler, to report errors.
 * @param r Relabel anlysis to set.
 * @param result Only return types matching this regular expression, or
 * NULL to return all types
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_relabel_analysis_set_result_regex(const apol_policy_t * p, apol_relabel_analysis_t * r, const char *result);

/******************** functions to access relabel results ********************/

/**
 * Return the relabelto vector embedded within an apol_relabel_result
 * node.  This is a vector of apol_relabel_result_pair_t objects.  The
 * caller shall not call apol_vector_destroy() upon this pointer.
 *
 * @param r Relabel result node.
 *
 * @return Pointer to a vector of rule pairs, relative to the policy
 * originally used to generate the relabelling result.
 */
	extern const apol_vector_t *apol_relabel_result_get_to(const apol_relabel_result_t * r);

/**
 * Return the relabelfrom vector embedded within an
 * apol_relabel_result node.  This is a vector of
 * apol_relabel_result_pair_t objects.  The caller shall not call
 * apol_vector_destroy() upon this pointer.
 *
 * @param r Relabel result node.
 *
 * @return Pointer to a vector of rule pairs, relative to the policy
 * originally used to generate the relabelling result.
 */
	extern const apol_vector_t *apol_relabel_result_get_from(const apol_relabel_result_t * r);

/**
 * Return the relabelboth vector embedded within an
 * apol_relabel_result node.  This is a vector of
 * apol_relabel_result_pair_t objects.  The caller shall not call
 * apol_vector_destroy() upon this pointer.
 *
 * @param r Relabel result node.
 *
 * @return Pointer to a vector of rule pairs, relative to the policy
 * originally used to generate the relabelling result.
 */
	extern const apol_vector_t *apol_relabel_result_get_both(const apol_relabel_result_t * r);

/**
 * Return the resulting type for an apol_relabel_result node.
 *
 * @param r Relabel result node.
 *
 * @return Pointer to a result type.
 */
	extern const qpol_type_t *apol_relabel_result_get_result_type(const apol_relabel_result_t * r);

/**
 * Return the first rule from an apol_relabel_result_pair object.
 *
 * For object mode analysis, this is the rule that affects the
 * starting type.  Either that type or one of its attributes will be
 * the target type for the returned rule.
 *
 * For subject mode analysis, this is a rule affects the starting
 * subject.  Either that subject or one of its attributes will be the
 * source type for the returned rule.
 *
 * @param p Relabel result pair object.
 *
 * @return Rule affecting the starting type/subject.
 */
	extern const qpol_avrule_t *apol_relabel_result_pair_get_ruleA(const apol_relabel_result_pair_t * p);

/**
 * Return the other rule from an apol_relabel_result_pair object.
 *
 * For object mode analysis, this is the rule that affects the
 * resulting type.  Either that type or one of its attributes will be
 * the target type for the returned rule.
 *
 * For subject mode analysis, the returned pointer will be NULL.
 *
 * @param p Relabel result pair object.
 *
 * @return Rule affecting the resulting type/subject (for object mode)
 * or NULL (for subject mode).
 */
	extern const qpol_avrule_t *apol_relabel_result_pair_get_ruleB(const apol_relabel_result_pair_t * p);

/**
 * Return the intermediate type for an apol_relabel_result_pair
 * object.
 *
 * For object mode analysis, this is the source type for the first
 * rule; it also will be the source type for the other rule.
 *
 * For subject mode analysis, the returned pointer will be NULL.
 *
 * @param p Relabel result pair object.
 *
 * @return Intermediate type for relabel result (for object mode) or
 * NULL (for subject mode).
 */
	extern const qpol_type_t *apol_relabel_result_pair_get_intermediate_type(const apol_relabel_result_pair_t * p);

#ifdef	__cplusplus
}
#endif

#endif
