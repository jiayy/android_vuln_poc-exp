/**
 *  @file
 *  Defines the public interface for searching and iterating over the permissive types.
 *
 *  @author Steve Lawrence slawrence@tresys.com
 *
 *  Copyright (C) 2006-2009 Tresys Technology, LLC
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

#ifndef QPOL_PERMISSIVE_QUERY_H
#define QPOL_PERMISSIVE_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>

	typedef struct qpol_permissive qpol_permissive_t;

/**
 *  Get an iterator for the permissive types in a policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_isid_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy 
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long 
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails, 
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_permissive_iter(const qpol_policy_t *policy, qpol_iterator_t **iter);


/**
 *  Get the name which identifies a permissive type from its datum.
 *  @param policy The policy with which the permissive type is associated.
 *  @param datum Permissive datum for which to get the name. Must be non-NULL.
 *  @param name Pointer to the string in which to store the name.
 *  Must be non-NULL. The caller should not free the string.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *name will be NULL.
 */
	extern int qpol_permissive_get_name(const qpol_policy_t *policy, const qpol_permissive_t *datum, const char **name);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_PERMISSIVE_QUERY_H */
