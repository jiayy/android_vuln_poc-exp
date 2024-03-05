/**
 *  @file
 *  Defines the public interface for searching and iterating over users.
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

#ifndef QPOL_USER_QUERY_H
#define QPOL_USER_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/mls_query.h>

	typedef struct qpol_user qpol_user_t;

/**
 *  Get the datum for a user by name.
 *  @param policy The policy from which to get the user.
 *  @param name The name of the user; searching is case sensitive.
 *  @param datum Pointer in which to store the user datum; the caller
 *  should not free this pointer.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and and *datum will be NULL.
 */
	extern int qpol_policy_get_user_by_name(const qpol_policy_t * policy, const char *name, const qpol_user_t ** datum);

/**
 *  Get an iterator for users declared in the policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator of type qpol_user_t* returned;
 *  the caller is responsible for calling qpol_iterator_destroy to
 *  free memory used; it is important to note that the iterator is
 *  valid only as long as the policy is unchanged.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_user_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter);

/**
 *  Get the integer value associated with a user. Values range from 1 to
 *  the number of users declared in the policy.
 *  @param policy The policy associate with the user.
 *  @param datum The user from which to get the value.
 *  @param value Pointer to the integer to set to value.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and value will be 0.
 */
	extern int qpol_user_get_value(const qpol_policy_t * policy, const qpol_user_t * datum, uint32_t * value);

/**
 *  Get an iterator for the set of roles assigned to a user.
 *  @param policy The policy associated with the user.
 *  @param datum The user from which to get the roles.
 *  @param roles Iterator of type qpol_role_t* returned;
 *  the caller is responsible for calling qpol_iterator_destroy to
 *  free memory used; it is important to note that the iterator is
 *  valid only as long as the policy is unchanged.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *roles will be NULL.
 */
	extern int qpol_user_get_role_iter(const qpol_policy_t * policy, const qpol_user_t * datum, qpol_iterator_t ** roles);

/**
 *  Get the allowed MLS range of a user.  If the policy is not MLS
 *  then the returned level will be NULL.
 *  @param policy The policy associated with the user.
 *  @param datum The user from which to get the range.
 *  @param range Pointer in which to store the range.  If the policy
 *  is not MLS then NULL will be assigned to the pointer.  The caller
 *  should not free this pointer.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *range will be NULL.
 */
	extern int qpol_user_get_range(const qpol_policy_t * policy, const qpol_user_t * datum, const qpol_mls_range_t ** range);

/**
 *  Get the default level for a user.  If the policy is not MLS then
 *  the returned level will be NULL.
 *  @param policy The policy associated with the user.
 *  @param datum The user from which to get the level.
 *  @param level Pointer in which to store the level.  If the policy
 *  is not MLS then NULL will be assigned to the pointer.  The caller
 *  should not free this pointer.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *level will be NULL.
 */
	extern int qpol_user_get_dfltlevel(const qpol_policy_t * policy, const qpol_user_t * datum,
					   const qpol_mls_level_t ** level);

/**
 *  Get the name which identifies a user from its datum.
 *  @param policy The policy associated with the user.
 *  @param datum The user for which to get the name.
 *  @param name Pointer in which to store the name; the caller
 *  should not free this string.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *name will be NULL.
 */
	extern int qpol_user_get_name(const qpol_policy_t * policy, const qpol_user_t * datum, const char **name);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_USER_QUERY_H */
