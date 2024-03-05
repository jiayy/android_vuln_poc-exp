/**
 *  @file
 *  Defines the public interface for searching and iterating over booleans.
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

#ifndef QPOL_BOOL_QUERY_H
#define QPOL_BOOL_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>
#include <qpol/policy.h>
#include <qpol/iterator.h>

	typedef struct qpol_bool qpol_bool_t;

/**
 *  Get the datum for a conditional boolean by name.
 *  @param policy The policy database from which to retrieve the boolean.
 *  @param name The name of the boolean; searching is case sensitive.
 *  @param datum Pointer to set to the boolean's datum entry in the policy.
 *  This memory should not be freed by the user.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *datum will be NULL.
 */
	extern int qpol_policy_get_bool_by_name(const qpol_policy_t * policy, const char *name, qpol_bool_t ** datum);

/**
 *  Get an iterator for conditional booleans in the policy.
 *  @param policy The policy database from which to create the iterator.
 *  @param iter Iterator of type qpol_bool_t* returned;
 *  the user is responsible for calling qpol_iterator_destroy to
 *  free memory used. It is also important to note that an iterator
 *  is only valid as long as the policy is unchanged.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_bool_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter);

/**
 *  Get the integer value associated with a boolean. Values range from 1 to
 *  the number of conditional booleans declared in the policy.
 *  @param policy The policy with which the boolean is associated.
 *  @param datum Boolean datum from which to get the value. Must be non-NULL.
 *  @param value Pointer to integer be set to value. Must be non-NULL.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *value will be 0.
 */
	extern int qpol_bool_get_value(const qpol_policy_t * policy, const qpol_bool_t * datum, uint32_t * value);

/**
 *  Get the state of a boolean.
 *  @param policy The policy with which the boolean is associated.
 *  @param datum Boolean datum from which to get the state. Must be non-NULL.
 *  @param state Pointer to the integer to be set to the boolean's state.
 *  Must be non-NULL.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *state will set to 0 (false).
 */
	extern int qpol_bool_get_state(const qpol_policy_t * policy, const qpol_bool_t * datum, int *state);

/**
 *  Set the state of a boolean and update the state of all conditionals
 *  using the boolean.
 *  @param policy The policy with which the boolean is associated.
 *  The state of the policy is changed by this function.
 *  @param datum Boolean datum for which to set the state. Must be non-NULL.
 *  @param state Value to which to set the state of the boolean.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set.
 */
	extern int qpol_bool_set_state(qpol_policy_t * policy, qpol_bool_t * datum, int state);

/**
 *  Set the state of a boolean but do not update the state of all conditionals
 *  using the boolean. The caller is responsible for calling
 *  qpol_policy_reevaluate_conds() at a later time to maintain a consistent
 *  state of conditional expressions.
 *  @param policy The policy with which the boolean is associated.
 *  The state of the policy is changed by this function.
 *  @param datum Boolean datum for which to set the state. Must be non-NULL.
 *  @param state Value to which to set the state of the boolean.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set.
 */
	extern int qpol_bool_set_state_no_eval(qpol_policy_t * policy, qpol_bool_t * datum, int state);

/**
 *  Get the name which identifies a boolean from its datum.
 *  @param policy The policy with which the boolean is associated.
 *  @param datum Boolean datum for which to get the name. Must be non-NULL.
 *  @param name Pointer to the string in which to store the name.
 *  Must be non-NULL. The caller should not free the string.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *name will be NULL.
 */
	extern int qpol_bool_get_name(const qpol_policy_t * policy, const qpol_bool_t * datum, const char **name);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_BOOL_QUERY_H */
