 /**
 *  @file
 *  Defines the public interface for searching and iterating over roles. 
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

#ifndef QPOL_ROLE_QUERY_H
#define QPOL_ROLE_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>

	typedef struct qpol_role qpol_role_t;

/**
 *  Get the datum for a role by name.
 *  @param policy The policy from which to get the role.
 *  @param name The name of the role; searching is case sensitive.
 *  @param datum Pointer in which to store the role datum; the caller
 *  should not free this pointer.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *datum will be NULL.
 */
	extern int qpol_policy_get_role_by_name(const qpol_policy_t * policy, const char *name, const qpol_role_t ** datum);

/**
 *  Get an iterator for roles declared in the policy.
 *  @param policy The policy with which to create the iterator.
 *  @param iter Iterator of type qpol_role_t* returned; 
 *  the caller is responsible for calling qpol_iterator_destroy to
 *  free memory used; it is important to note that the iterator 
 *  is valid only as long as the policy is unchanged.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_role_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter);

/**
 *  Get the integer value associated with a role; values range from
 *  1 to the number of declared roles. 
 *  @param policy The policy associated with the role.
 *  @param datum The role from which to get the value.
 *  @param value Pointer to the integer to set to value. Must be non-NULL.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and value will be 0.
 */
	extern int qpol_role_get_value(const qpol_policy_t * policy, const qpol_role_t * datum, uint32_t * value);

/**
 *  Get an iterator for the set of roles dominated by a role.
 *  @param policy The policy associated with the role.
 *  @param datum The role from which to get the dominated roles.
 *  @param dominates Iterator of type qpol_role_t* returned; 
 *  the caller is responsible for calling qpol_iterator_destroy to
 *  free memory used; it is important to note that the iterator is
 *  valid only as long as the policy is unchanged. Note: By 
 *  convention a role always dominates itself, so the user of this
 *  iterator should always check for this case.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *dominates will be NULL.
 */
	extern int qpol_role_get_dominate_iter(const qpol_policy_t * policy, const qpol_role_t * datum,
					       qpol_iterator_t ** dominates);

/**
 *  Get an iterator for the set of types assigned to a role.
 *  @param policy The policy associated with the role.
 *  @param datum The role from which to get the types.
 *  @param types Iterator of type qpol_type_t* returned; 
 *  the caller is responsible for calling qpol_iterator_destroy to
 *  free memory used; it is important to note that the iterator
 *  is valid only as long as the policy is unchanged.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and types will be NULL.
 */
	extern int qpol_role_get_type_iter(const qpol_policy_t * policy, const qpol_role_t * datum, qpol_iterator_t ** types);

/**
 *  Get the name by which a role is identified from its datum.
 *  @param policy The policy associated with the role.
 *  @param datum The role for which to get the name.
 *  @param name Pointer in which to store the name; the caller
 *  should not free this string.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *name will be NULL.
 */
	extern int qpol_role_get_name(const qpol_policy_t * policy, const qpol_role_t * datum, const char **name);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_ROLE_QUERY_H */
