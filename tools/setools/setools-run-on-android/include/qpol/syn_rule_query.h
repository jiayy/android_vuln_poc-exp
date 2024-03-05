/**
 *  @file
 *  Public interface for querying syntactic rules from the extended
 *  policy image.
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

#ifndef QPOL_SYN_RULE_QUERY_H
#define QPOL_SYN_RULE_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <qpol/policy.h>
#include <qpol/cond_query.h>
#include <qpol/iterator.h>
#include <stdint.h>

	typedef struct qpol_type_set qpol_type_set_t;
	typedef struct qpol_syn_avrule qpol_syn_avrule_t;
	typedef struct qpol_syn_terule qpol_syn_terule_t;

/**
 *  Get an iterator of the included types in a type set.
 *  @param policy Policy associated with the type set.
 *  @param ts Type set from which to get the included types.
 *  @param iter Iterator over items of type qpol_type_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_type_set_get_included_types_iter(const qpol_policy_t * policy, const qpol_type_set_t * ts,
							 qpol_iterator_t ** iter);

/**
 *  Get an iterator of the subtracted types in a type set.
 *  @param policy Policy associated with the type set.
 *  @param ts Type set from which to get the subtracted types.
 *  @param iter Iterator over items of type qpol_type_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_type_set_get_subtracted_types_iter(const qpol_policy_t * policy, const qpol_type_set_t * ts,
							   qpol_iterator_t ** iter);

/**
 *  Determine if a type set includes '*'.
 *  @param policy Policy associated with the type set.
 *  @param ts Type set to check for '*'.
 *  @param is_star Pointer to integer to set.
 *  Will be set to 1 if ts contains '*' or 0 otherwise.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *is_star will be 0.
 */
	extern int qpol_type_set_get_is_star(const qpol_policy_t * policy, const qpol_type_set_t * ts, uint32_t * is_star);

/**
 *  Determine if a type set is complemented (contains '~').
 *  @param policy Policy associated with the type set.
 *  @param ts Type set to check for complement.
 *  @param is_comp Pointer to integer to set.
 *  Will be set to 1 if ts is complemented or 0 otherwise.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *is_comp will be 0.
 */
	extern int qpol_type_set_get_is_comp(const qpol_policy_t * policy, const qpol_type_set_t * ts, uint32_t * is_comp);

/**
 *  Get the rule type of a syntactic avrule.
 *  @param policy Policy associated with the rule.
 *  @param rule Avrule from which to get the type.
 *  @param rule_type Pointer to integer to set.
 *  Will be one of QPOL_RULE_* (see qpol/avrule_query.h).
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *rule_type will be 0.
 */
	extern int qpol_syn_avrule_get_rule_type(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule,
						 uint32_t * rule_type);

/**
 *  Get the set of types specified for a syntatic rule's source field.
 *  @param policy Policy associated with the rule.
 *  @param rule Avrule from which to get the source type set.
 *  @param source_set Type set returned; the caller <b>should not</b>
 *  free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *source_set will be NULL.
 */
	extern int qpol_syn_avrule_get_source_type_set(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule,
						       const qpol_type_set_t ** source_set);

/**
 *  Get the set of types specified for a syntactic rule's target field.
 *  @param policy Policy associated with the rule.
 *  @param rule Avrule from which to get the target type set.
 *  @param target_set Type set returned; the caller <b>should not</b>
 *  free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *target_set will be NULL.
 */
	extern int qpol_syn_avrule_get_target_type_set(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule,
						       const qpol_type_set_t ** target_set);

/**
 *  Determine if a syntactic rule includes the self flag in the target set.
 *  @param policy Policy associated with the rule.
 *  @param rule Avrule to check for the self flag.
 *  @param is_self Pointer to the integer to set; if the rule includes self,
 *  this will be set to 1, otherwise it will be set to 0.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *is_self will be 0.
 */
	extern int qpol_syn_avrule_get_is_target_self(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule,
						      uint32_t * is_self);

/**
 *  Get an iterator over all classes specified in a syntactic rule.
 *  @param policy Policy associated with the rule.
 *  @param rule The rule from which to get the classes.
 *  @param classes Iterator over items of type qpol_class_t* returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *classes will be NULL.
 */
	extern int qpol_syn_avrule_get_class_iter(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule,
						  qpol_iterator_t ** classes);

/**
 *  Get an iterator over all permissions specified in a syntactic rule.
 *  @param policy Policy associated with the
 *  @param rule The rule from which to get the permissions.
 *  @param perms Iterator over items of type char* returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *perms will be NULL.
 */
	extern int qpol_syn_avrule_get_perm_iter(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule,
						 qpol_iterator_t ** perms);

/**
 *  Get the line number of a syntactic rule.
 *  @param policy Policy associated with the rule
 *  @param rule The rule for which to get the line number.
 *  @param lineno Pointer to set to the line number.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *lineno will be 0.
 */
	extern int qpol_syn_avrule_get_lineno(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule, unsigned long *lineno);

/**
 *  If the syntactic rule is within a conditional, then get that
 *  conditional and assign it to cond.  Otherwise assign to cond NULL.
 *  @param policy Policy associated with the rule.
 *  @param rule The rule for which to get the conditional.
 *  @param cond Reference pointer to this rule's conditional
 *  expression, or NULL if the rule is unconditional.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *lineno will be 0.
 */
	extern int qpol_syn_avrule_get_cond(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule,
					    const qpol_cond_t ** cond);

/**
 *  Determine if the syntactic rule is enabled.  Unconditional rules
 *  are always enabled.
 *  @param policy Policy associated with the rule.
 *  @param rule The rule for which to get the conditional.
 *  @param is_enabled Integer in which to store the result: set to 1
 *  if enabled and 0 otherwise.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *lineno will be 0.
 */
	extern int qpol_syn_avrule_get_is_enabled(const qpol_policy_t * policy, const qpol_syn_avrule_t * rule,
						  uint32_t * is_enabled);

/**
 *  Get the rule type of a syntactic terule.
 *  @param policy Policy associated with the rule.
 *  @param rule Terule from which to get the type.
 *  @param rule_type Pointer to integer to set.
 *  Will be one of QPOL_RULE_TYPE_* (see qpol/terule_query.h).
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *rule_type will be 0.
 */
	extern int qpol_syn_terule_get_rule_type(const qpol_policy_t * policy, const qpol_syn_terule_t * rule,
						 uint32_t * rule_type);

/**
 *  Bet the set of types specified for a syntactic rule's source field.
 *  @param policy Policy associated with the rule.
 *  @param rule Terule from which to get the source type set.
 *  @param source_set Type set returned; the caller <b>shoule not</b>
 *  free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *source_set will be NULL.
 */
	extern int qpol_syn_terule_get_source_type_set(const qpol_policy_t * policy, const qpol_syn_terule_t * rule,
						       const qpol_type_set_t ** source_set);

/**
 *  Get the set of types specified for a syntactic rule's target field.
 *  @param policy Policy associated with the rule.
 *  @param rule Terule from which to get the target types et.
 *  @param target_set Type set returned; ther caller <b>should not</b>
 *  free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *target_set will be NULL.
 */
	extern int qpol_syn_terule_get_target_type_set(const qpol_policy_t * policy, const qpol_syn_terule_t * rule,
						       const qpol_type_set_t ** target_set);

/**
 *  Get an iterator over all classes specified in a syntactic rule.
 *  @param policy Policy associated with the rule.
 *  @param rule The rule from which to get the classes.
 *  @param classes Iterator over items of type qpol_class_t* returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *classes will be NULL.
 */
	extern int qpol_syn_terule_get_class_iter(const qpol_policy_t * policy, const qpol_syn_terule_t * rule,
						  qpol_iterator_t ** classes);

/* forward declaration */
	struct qpol_type;

/**
 *  Get the default type of a syntactic terule.
 *  @param policy Policy associated with the rule.
 *  @param rule Terule from which to et the default type.
 *  @param dflt Reference pointer to the type to return.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *dflt will be NULL.
 */
	extern int qpol_syn_terule_get_default_type(const qpol_policy_t * policy, const qpol_syn_terule_t * rule,
						    const struct qpol_type **dflt);

/**
 *  Get the line number of a syntactic rule.
 *  @param policy Policy associated with the rule.
 *  @param rule The rule for which to get the line number.
 *  @param lineno Pointer to set to the line number.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *lineno will be 0.
 */
	extern int qpol_syn_terule_get_lineno(const qpol_policy_t * policy, const qpol_syn_terule_t * rule, unsigned long *lineno);

/**
 *  If the syntactic rule is within a conditional, then get that
 *  conditional and assign it to cond.  Otherwise assign to cond NULL.
 *  @param policy Policy associated with the rule.
 *  @param rule The rule for which to get the conditional.
 *  @param cond Reference pointer to this rule's conditional
 *  expression, or NULL if the rule is unconditional.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *lineno will be 0.
 */
	extern int qpol_syn_terule_get_cond(const qpol_policy_t * policy, const qpol_syn_terule_t * rule,
					    const qpol_cond_t ** cond);

/**
 *  Determine if the syntactic rule is enabled.  Unconditional rules
 *  are always enabled.
 *  @param policy Policy associated with the rule.
 *  @param rule The rule for which to get the conditional.
 *  @param is_enabled Integer in which to store the result: set to 1
 *  if enabled and 0 otherwise.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *lineno will be 0.
 */
	extern int qpol_syn_terule_get_is_enabled(const qpol_policy_t * policy, const qpol_syn_terule_t * rule,
						  uint32_t * is_enabled);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_SYN_RULE_QUERY_H */
