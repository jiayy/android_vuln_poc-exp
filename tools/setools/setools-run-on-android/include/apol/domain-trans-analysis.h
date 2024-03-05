/**
 * @file
 *
 * Routines to perform a domain transition analysis.
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

#ifndef APOL_DOMAIN_TRANS_ANALYSIS_H
#define APOL_DOMAIN_TRANS_ANALYSIS_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include <qpol/policy.h>

	typedef struct apol_domain_trans_analysis apol_domain_trans_analysis_t;
	typedef struct apol_domain_trans_result apol_domain_trans_result_t;

#define APOL_DOMAIN_TRANS_DIRECTION_FORWARD 0x01
#define APOL_DOMAIN_TRANS_DIRECTION_REVERSE 0x02

#define APOL_DOMAIN_TRANS_SEARCH_VALID		0x01
#define APOL_DOMAIN_TRANS_SEARCH_INVALID	0x02
#define APOL_DOMAIN_TRANS_SEARCH_BOTH		(APOL_DOMAIN_TRANS_SEARCH_VALID|APOL_DOMAIN_TRANS_SEARCH_INVALID)

/******************* table operation functions ****************************/

/**
 *  Build the table of domain transitions for a policy if not already built.
 *  @param policy The policy for which to build the table; if the table
 *  already exists for this policy, nothing is done.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and the table will be destroyed.
 */
	extern int apol_policy_build_domain_trans_table(apol_policy_t * policy);

/**
 * @deprecated Use apol_policy_build_domain_trans_table().
 */
	extern int apol_policy_domain_trans_table_build(apol_policy_t * policy) __attribute__ ((deprecated));

/**
 *  Reset the state of the domain transition table in a policy.  This
 *  is needed because by default subsequent calls to
 *  apol_domain_trans_analysis_do() will not produce results generated
 *  in a previous call.  If calls are to be considered independent or
 *  calls in a different direction are desired, call this function
 *  prior to apol_domain_trans_analysis_do().  If the table was not
 *  built yet then this function does nothing.
 *
 *  @param policy Policy containing the table for which the state
 *  should be reset.
 */
	extern void apol_policy_reset_domain_trans_table(apol_policy_t * policy);

/**
 * @deprecated Use apol_policy_reset_domain_trans_table().
 */
	extern void apol_domain_trans_table_reset(apol_policy_t * policy) __attribute__ ((deprecated));

/*************** functions to do domain transition anslysis ***************/

/**
 *  Allocate and return a new domain transition analysis structure. All
 *  fields are cleared; one must fill in the details of the analysis
 *  before running it. The caller must call apol_domain_trans_analysis_destroy()
 *  upon the return value afterwards.
 *  @return An initialized domain transition analysis structure, or NULL
 *  upon error; if an error occurs errno will be set.
 */
	extern apol_domain_trans_analysis_t *apol_domain_trans_analysis_create(void);

/**
 *  Deallocate all memory associated with the referenced domain transition
 *  analysis structure, and then set it to NULL. This function does nothing if
 *  the analysis is already NULL.
 *  @param dta Reference to a domain transition analysis structure to destroy.
 */
	extern void apol_domain_trans_analysis_destroy(apol_domain_trans_analysis_t ** dta);

/**
 *  Set the direction of the transitions with respect to the start type.
 *  Must be either APOL_DOMAIN_TRANS_DIRECTION_FORWARD
 *  or APOL_DOMAIN_TRANS_DIRECTION_REVERSE.
 *  @param policy Policy handler, to report errors.
 *  @param dta Domain transition analysis to set.
 *  @param direction The direction to analyze using one of the two values above.
 *  @return 0 on success, and < 0 on error; if the call fails,
 *  errno will be set and dta will be unchanged.
 */
	extern int apol_domain_trans_analysis_set_direction(const apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
							    unsigned char direction);

/**
 *  Set the analysis to search for transitions based upon whether they
 *  would be permitted. The value must be one of APOL_DOMAIN_TRANS_SEARCH_*
 *  defined above. The default for a newly created analysis is to search
 *  for only valid transitions (i.e. APOL_DOMAIN_TRANS_SEARCH_VALID).
 *  @param policy Policy handler, to report errors.
 *  @param dta Domain transition analysis to set.
 *  @param valid One of APOL_DOMAIN_TRANS_SEARCH_*.
 *  @return 0 on success, and < 0 on error; if the call fails,
 *  errno will be set and dta will be unchanged.
 */
	extern int apol_domain_trans_analysis_set_valid(const apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
							unsigned char valid);

/**
 *  Set the analysis to begin searching using a given type. This function
 *  must be called prior to running the analysis. If a previous type
 *  was set, it will be free()'d first.
 *  @param policy Policy handler, to report errors.
 *  @param dta Domain transition analysis to set.
 *  @param type_name Name of the type from which to begin searching.
 *  Must be non-NULL. This string will be duplicated.
 *  @return 0 on success, and < 0 on error; if the call fails,
 *  errno will be set and dta will be unchanged.
 */
	extern int apol_domain_trans_analysis_set_start_type(const apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
							     const char *type_name);

/**
 *  Set the analysis to return only types matching a regular expression.
 *  Note that the regular expression will also match types' aliases.
 *  @param policy Policy handler, to report errors.
 *  @param dta Domain transition analysis to set.
 *  @param result Only return results matching this regular expression, or
 *  NULL to return all types.
 *  @return 0 on success, and < 0 on failure; if the call fails,
 *  errno will be set.
 */
	extern int apol_domain_trans_analysis_set_result_regex(const apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
							       const char *regex);

/**
 *  Set the analysis to return only types having access (via allow
 *  rules) to this type. <b>This is only valid for forward
 *  analysis.</b> If more than one type is appended to the query, the
 *  resulting type must have access to at least one of the appended
 *  types. Pass a NULL to clear all previously appended types. <b>If
 *  access types are appended, the caller must also call
 *  apol_domain_trans_analysis_append_class() at least once with
 *  a valid class and apol_domain_trans_analysis_append_perm() at
 *  least once with a valid permission.</b>
 *  @param policy Policy handler, to report errors.
 *  @param dta Domain transition analysis to set.
 *  @param type_name Type to which a result must have access.
 *  @return 0 on success, and < 0 on error; if the call fails,
 *  errno will be set and dta will be unchanged.
 */
	extern int apol_domain_trans_analysis_append_access_type(const apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
								 const char *type_name);

/**
 *  Set the analysis to return only types having access (via allow
 *  rules) to this class with the given permission. <b>This is only
 *  valid for forward analysis.</b> If more than one class is appended
 *  to the query, the resulting type must have access to at least one
 *  of the appended classes.  If more than one permission is appended
 *  for the same class, the resulting type must have at least one of
 *  the appended permissions for that class.  Pass a NULL to both
 *  strings to clear all previously appended classes and
 *  permissions. <b>If access classes and permissions are appended,
 *  the caller must also call
 *  apol_domain_trans_analysis_append_access_type() at least once with
 *  a valid type.</b>
 *  @param policy Policy handler, to report errors.
 *  @param dta Domain transition analysis to set.
 *  @param class_name The class to which a result must have access.
 *  @param perm_name The permission which a result must have
 *  for the given class.
 *  @return 0 on success, and < 0 on error; if the call fails,
 *  errno will be set and dta will be unchanged.
 *  @deprecated This function has been split into
 *  apol_domain_trans_analysis_append_class() and
 *  apol_domain_trans_analysis_append_perm()
 */
	extern int apol_domain_trans_analysis_append_class_perm(const apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
								const char *class_name, const char *perm_name)
		__attribute__ ((deprecated));

/**
 *  Set the analysis to return only types having access (via allow
 *  rules) to this class. <b>This is only valid for forward
 *  analysis.</b> If more than one class is appended to the query, the
 *  resulting type must have access to at least one of the appended
 *  classes.  Pass a NULL to clear all previously appended classes.
 *  <b>If access classes are appended, the caller must also call
 *  apol_domain_trans_analysis_append_access_type() at least once with
 *  a valid type and apol_domain_trans_analysis_append_perm() with a
 *  valid permission.</b>
 *  @param policy Policy handler, to report errors.
 *  @param dta Domain transition analysis to set.
 *  @param class_name The class to which a result must have access.
 *  @return 0 on success, and < 0 on error; if the call fails,
 *  errno will be set and dta will be unchanged.
 */
	extern int apol_domain_trans_analysis_append_class(const apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
							   const char *class_name);

/**
 *  Set the analysis to return only types having access (via allow
 *  rules) to this permission. <b>This is only valid for forward
 *  analysis.</b> If more than one permission is appended the
 *  resulting type must have at least one of the appended permissions.
 *  Pass a NULL to clear all previously appended permissions. <b>If
 *  access permissions are appended, the caller must also call
 *  apol_domain_trans_analysis_append_access_type() at least once with
 *  a valid type and apol_domain_trans_analysis_append_class() at
 *  least once with a valid class.</b>
 *  @param policy Policy handler, to report errors.
 *  @param dta Domain transition analysis to set.
 *  @param perm_name The permission which a result must have.
 *  @return 0 on success, and < 0 on error; if the call fails,
 *  errno will be set and dta will be unchanged.
 */
	extern int apol_domain_trans_analysis_append_perm(const apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
							  const char *perm_name);

/**
 *  Execute a domain transition analysis against a particular policy.
 *  @param policy Policy containing the table to use.
 *  @param dta A non-NULL structure containng parameters for analysis.
 *  @param results A reference pointer to a vector of
 *  apol_domain_trans_result_t. The vector will be allocated by this
 *  function.  The caller must call apol_vector_destroy()
 *  afterwards. This will be set to NULL upon error.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *results will be NULL.
 *
 *  @see apol_policy_reset_domain_trans_table()
 */
	extern int apol_domain_trans_analysis_do(apol_policy_t * policy, apol_domain_trans_analysis_t * dta,
						 apol_vector_t ** results);

/***************** functions for accessing results ************************/

/**
 *  Return the start type of the transition in an
 *  apol_domain_trans_result node.  The caller should not free the
 *  returned pointer.  If the transition in the node is not valid
 *  there may be no start type in which case NULL is returned.
 *  @param dtr Domain transition result node.
 *  @return Pointer to the start type of the transition.
 */
	extern const qpol_type_t *apol_domain_trans_result_get_start_type(const apol_domain_trans_result_t * dtr);

/**
 *  Return the entrypoint type of the transition in an
 *  apol_domain_trans_result node.  The caller should not free the
 *  returned pointer.  If the transition in the node is not valid
 *  there may be no entrypoint in which case NULL is returned.
 *  @param dtr Domain transition result node.
 *  @return Pointer to the entrypoint type of the transition.
 */
	extern const qpol_type_t *apol_domain_trans_result_get_entrypoint_type(const apol_domain_trans_result_t * dtr);

/**
 *  Return the end type of the transition in an apol_domain_trans_result
 *  node. The caller should not free the returned pointer. If the transition
 *  in the node is not valid there may be no end type in which case NULL
 *  is returned.
 *  @param dtr Domain transition result node.
 *  @return Pointer to the start type of the transition.
 */
	extern const qpol_type_t *apol_domain_trans_result_get_end_type(const apol_domain_trans_result_t * dtr);

/**
 *  Return the vector of process transition rules (qpol_avrule_t
 *  pointers) in an apol_domain_trans_result node.  The caller should
 *  not free the returned pointer.  If the transition is invalid then
 *  the returned vector will be empty.
 *  @param dtr Domain transition result node.
 *  @return Vector of qpol_avrule_t relative to the policy originally
 *  used to generate the results.
 */
	extern const apol_vector_t *apol_domain_trans_result_get_proc_trans_rules(const apol_domain_trans_result_t * dtr);

/**
 *  Return the vector of file entrypoint rules (qpol_avrule_t
 *  pointers) in an apol_domain_trans_result node.  The caller should
 *  not free the returned pointer.  If the transition is invalid then
 *  the returned vector will be empty.
 *  @return Vector of qpol_avrule_t relative to the policy originally
 *  used to generate the results.
 */
	extern const apol_vector_t *apol_domain_trans_result_get_entrypoint_rules(const apol_domain_trans_result_t * dtr);

/**
 *  Return the vector of file execute rules (qpol_avrule_t pointers)
 *  in an apol_domain_trans_result node.  The caller should not free
 *  the returned pointer.  If the transition is invalid then the
 *  returned vector will be empty.
 *  @return Vector of qpol_avrule_t relative to the policy originally
 *  used to generate the results.
 */
	extern const apol_vector_t *apol_domain_trans_result_get_exec_rules(const apol_domain_trans_result_t * dtr);

/**
 *  Return the vector of process setexec rules (qpol_avrule_t
 *  pointers) in an apol_domain_trans_result node.  The caller should
 *  not free the returned pointer.  For all policies of version 15 or
 *  later a transition requires either a setexec rule or a
 *  type_transition rule to be valid.  Valid transitions may have
 *  both; if there is no rule, this function returns an empty vector.
 *  @param dtr Domain transition result node.
 *  @return Vector of qpol_avrule_t relative to the policy originally
 *  used to generate the results.
 */
	extern const apol_vector_t *apol_domain_trans_result_get_setexec_rules(const apol_domain_trans_result_t * dtr);

/**
 *  Return the vector of type_transition rules (qpol_terule_t
 *  pointers) in an apol_domain_trans_result node.  The caller should
 *  not free the returned pointer.  For all policies of version 15 or
 *  later a transition requires either a setexec rule or a
 *  type_transition rule to be valid.  Valid transitions may have
 *  both; if there is no rule, this function returns an empty vector.
 *  @param dtr Domain transition result node.
 *  @return Vector of qpol_terule_t relative to the policy originally
 *  used to generate the results.
 */
	extern const apol_vector_t *apol_domain_trans_result_get_type_trans_rules(const apol_domain_trans_result_t * dtr);

/**
 *  Determine if the transition in an apol_domain_trans_result node is valid.
 *  @param dtr Domain transition result node.
 *  @return 0 if invalid and non-zero if valid. If dtr is NULL, returns 0.
 */
	extern int apol_domain_trans_result_is_trans_valid(const apol_domain_trans_result_t * dtr);

/**
 *  Return the vector of access rules which satisfied the access
 *  types, classes, and permissions specified in the query. This is a
 *  vector of qpol_avrule_t pointers. The caller <b>should not</b>
 *  call apol_vector_destroy() upon the returned vector. This vector
 *  is only populated if access criteria were specified in the
 *  analysis.
 *
 *  @param dtr Domain transition result node.
 *  @return Pointer to a vector of rules relative to the policy originally
 *  used to generate the results.
 */
	extern const apol_vector_t *apol_domain_trans_result_get_access_rules(const apol_domain_trans_result_t * dtr);

/**
 * Do a deep copy (i.e., a clone) of an apol_domain_trans_result_t
 * object.  The caller is responsible for calling
 * apol_domain_trans_result_destroy() upon the returned value.
 *
 * @param result Pointer to a domain trans result structure to
 * destroy.
 *
 * @return A clone of the passed in result node, or NULL upon error.
 */
	extern apol_domain_trans_result_t *apol_domain_trans_result_create_from_domain_trans_result(const apol_domain_trans_result_t
												    * in);

/**
 * Free all memory used by an apol_domain_trans_result_t object and
 * set it to NULL.  This does nothing if the pointer is already NULL.
 * <b>This should only be called for results created by
 * apol_domain_trans_result_create_from_domain_trans_result() and not
 * those returned from within vectors.</b>
 *
 * @param res Reference pointer to a result to destroy.
 */
	extern void apol_domain_trans_result_destroy(apol_domain_trans_result_t ** res);

/************************ utility functions *******************************/
/* define the following for rule type */
#define APOL_DOMAIN_TRANS_RULE_PROC_TRANS       0x01
#define APOL_DOMAIN_TRANS_RULE_EXEC             0x02
#define APOL_DOMAIN_TRANS_RULE_EXEC_NO_TRANS    0x04
#define APOL_DOMAIN_TRANS_RULE_ENTRYPOINT       0x08
#define APOL_DOMAIN_TRANS_RULE_TYPE_TRANS       0x10
#define APOL_DOMAIN_TRANS_RULE_SETEXEC          0x20

/**
 *  Verify that a transition using the given three types is valid in the given
 *  policy. If not valid, return a value indicating the missing rules. If any
 *  type is NULL, rules that would contain that type are considered missing. A
 *  valid transition requires a process transition, an entrypoint, and an
 *  execute rule. If the policy is version 15 or later it also requires either
 *  a setexec rule or a type_transition rule.  The value
 *  APOL_DOMAIN_TRANS_RULE_EXEC_NO_TRANS is not returned by this function.
 *
 *  @param policy The policy containing the domain transition table to
 *  consult. Must be non-NULL.
 *  @param start_dom The starting domain of the transition. May be NULL.
 *  @param ep_type The entrypoint of the transition. May be NULL.
 *  @param end_dom The ending domain of the transition. May be NULL.
 *
 *  @return 0 if the transition is valid, < 0 on error, or a bit-wise
 *  or'ed set of APOL_DOMAIN_TRANS_RULE_* from above (always > 0)
 *  representing the rules missing from the transition.
 */
	extern int apol_domain_trans_table_verify_trans(apol_policy_t * policy, const qpol_type_t * start_dom,
							const qpol_type_t * ep_type, const qpol_type_t * end_dom);

#ifdef	__cplusplus
}
#endif

#endif				       /* APOL_DOMAIN_TRANS_ANALYSIS_H */
