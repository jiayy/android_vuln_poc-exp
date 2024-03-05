/**
 *  @file
 *  Defines public interface for iterating over RBAC rules.
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

#ifndef QPOL_RBACRULE_QUERY
#define QPOL_RBACRULE_QUERY

#ifdef	__cplusplus
extern "C"
{
#endif

#include <qpol/policy.h>
#include <qpol/iterator.h>

	typedef struct qpol_role_allow qpol_role_allow_t;
	typedef struct qpol_role_trans qpol_role_trans_t;

/**
 *  Get an iterator over all role allow rules in the policy.
 *  @param policy Policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_role_allow_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_role_allow_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter);

/**
 *  Get the source role from a role allow rule.
 *  @param policy The policy from which the rule comes.
 *  @param rule The rule from which to get the source role.
 *  @param source Pointer in which to store the source role.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *source will be NULL.
 */
	extern int qpol_role_allow_get_source_role(const qpol_policy_t * policy, const qpol_role_allow_t * rule,
						   const qpol_role_t ** source);

/**
 *  Get the target role from a role allow rule.
 *  @param policy The policy from which the rule comes.
 *  @param rule The rule from which to get the target role.
 *  @param target Pointer in which to store the target role.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *target will be NULL.
 */
	extern int qpol_role_allow_get_target_role(const qpol_policy_t * policy, const qpol_role_allow_t * rule,
						   const qpol_role_t ** target);

/**
 *  Get an iterator over all role transition rules in the policy.
 *  @param policy Policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_role_trans_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_role_trans_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter);

/**
 *  Get the source role from a role transition rule.
 *  @param policy The policy from which the rule comes.
 *  @param rule The rule from which to get the source role.
 *  @param source Pointer in which to store the source role.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *source will be NULL.
 */
	extern int qpol_role_trans_get_source_role(const qpol_policy_t * policy, const qpol_role_trans_t * rule,
						   const qpol_role_t ** source);

/**
 *  Get the target type from a role transition rule.
 *  @param policy The policy from which the rule comes.
 *  @param rule The rule from which to get the target type.
 *  @param target Pointer in which to store the target type.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *target will be NULL.
 */
	extern int qpol_role_trans_get_target_type(const qpol_policy_t * policy, const qpol_role_trans_t * rule,
						   const qpol_type_t ** target);

/**
 *  Get the default role from a role transition rule.
 *  @param policy The policy from which the rule comes.
 *  @param rule The rule from which to get the default role.
 *  @param dflt Pointer in which to store the default role.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *dflt will be NULL.
 */
	extern int qpol_role_trans_get_default_role(const qpol_policy_t * policy, const qpol_role_trans_t * rule,
						    const qpol_role_t ** dflt);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_RBACRULE_QUERY */
