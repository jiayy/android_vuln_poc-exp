/**
 *  @file
 *  Defines the public interface for searching and iterating over type rules.
 *
 *  @author Kevin Carr kcarr@tresys.com
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

#ifndef QPOL_TERULE_QUERY_H
#define QPOL_TERULE_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <qpol/policy.h>
#include <qpol/cond_query.h>

	typedef struct qpol_terule qpol_terule_t;

/* rule type defines (values copied from "sepol/policydb/policydb.h") */
#define QPOL_RULE_TYPE_TRANS   16
#define QPOL_RULE_TYPE_CHANGE  64
#define QPOL_RULE_TYPE_MEMBER  32

/**
 *  Get an iterator over all type rules in a policy of a rule type in
 *  rule_type_mask. It is an error to call this function if rules are not
 *  loaded.
 *  @param policy Policy from which to get the av rules.
 *  @param rule_type_mask Bitwise or'ed set of QPOL_RULE_TYPE_* values.
 *  It is an error to specify any other values of QPOL_RULE_* in the mask.
 *  @param iter Iterator over items of type qpol_terule_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_terule_iter(const qpol_policy_t * policy, uint32_t rule_type_mask, qpol_iterator_t ** iter);

/**
 *  Get the source type from a type rule.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the source type.
 *  @param source Pointer in which to store the source type.
 *  The caller should not free this pointer.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *source will be NULL.
 */
	extern int qpol_terule_get_source_type(const qpol_policy_t * policy, const qpol_terule_t * rule,
					       const qpol_type_t ** source);

/**
 *  Get the target type from a type rule.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the target type.
 *  @param target Pointer in which to store the target type.
 *  The caller should not free this pointer.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *target will be NULL.
 */
	extern int qpol_terule_get_target_type(const qpol_policy_t * policy, const qpol_terule_t * rule,
					       const qpol_type_t ** target);

/**
 *  Get the object class from a type rule.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the object class.
 *  @param obj_class Pointer in which to store the object class.
 *  The caller should not free this pointer.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *obj_class will be NULL.
 */
	extern int qpol_terule_get_object_class(const qpol_policy_t * policy, const qpol_terule_t * rule,
						const qpol_class_t ** obj_class);

/**
 *  Get the default type from a type rule.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the default type.
 *  @param dflt Pointer in which to store the default type.
 *  The caller should not free this pointer.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *dflt will be NULL.
 */
	extern int qpol_terule_get_default_type(const qpol_policy_t * policy, const qpol_terule_t * rule,
						const qpol_type_t ** dflt);

/**
 *  Get the rule type value for a type rule.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the rule type.
 *  @param rule_type Integer in which to store the rule type value.
 *  The value will be one of the QPOL_RULE_* values above.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *rule_type will be 0.
 */
	extern int qpol_terule_get_rule_type(const qpol_policy_t * policy, const qpol_terule_t * rule, uint32_t * rule_type);

/**
 *  Get the conditional from which a type rule comes. If the rule
 *  is not a conditional rule *cond is set to NULL.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the conditional.
 *  @param cond The conditional returned. (NULL if rule is not conditional)
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *cond will be NULL. If the rule is not conditional
 *  *cond is set to NULL and the function is considered successful.
 */
	extern int qpol_terule_get_cond(const qpol_policy_t * policy, const qpol_terule_t * rule, const qpol_cond_t ** cond);

/**
 *  Determine if a rule is enabled. Unconditional rules are always enabled.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule to check.
 *  @param is_enabled Integer in which to store the result: set to 1 if enabled
 *  and 0 otherwise.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *is_enabled will be 0.
 */
	extern int qpol_terule_get_is_enabled(const qpol_policy_t * policy, const qpol_terule_t * rule, uint32_t * is_enabled);

/**
 *  Get the list (true or false) in which a conditional rule is. It is
 *  an error to call this function for an unconditional rule.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule to check.
 *  @param which_list Integer in which to store the result: set to 1 if
 *  rule is in the true list or 0 if in the false list.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *which_list will be 0.
 */
	extern int qpol_terule_get_which_list(const qpol_policy_t * policy, const qpol_terule_t * rule, uint32_t * which_list);

#ifdef	__cplusplus
}
#endif

#endif
