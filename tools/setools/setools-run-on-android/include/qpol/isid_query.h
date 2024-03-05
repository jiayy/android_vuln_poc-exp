/**
 *  @file
 *  Defines the public interface for searching and iterating over initial SIDs.
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

#ifndef QPOL_ISID_QUERY_H
#define QPOL_ISID_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>

	typedef struct qpol_isid qpol_isid_t;

/**
 *  Get an initial SID statement by name.
 *  @param policy The policy from which to get the initial SID statement.
 *  @param name The name of the initial SID.
 *  @param ocon Pointer in which to store the initial SID.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *ocon will be NULL.
 */
	extern int qpol_policy_get_isid_by_name(const qpol_policy_t * policy, const char *name, const qpol_isid_t ** ocon);

/**
 *  Get an iterator for the initial SID statements in a policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_isid_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy 
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long 
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails, 
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_isid_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter);

/**
 *  Get the name from an initial SID statement.
 *  @param policy The policy associated with the initial SID.
 *  @param ocon The initial SID from which to get the name.
 *  @param name Pointer to the string in which to store the name.
 *  The caller should not free this string.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *name will be NULL.
 */
	extern int qpol_isid_get_name(const qpol_policy_t * policy, const qpol_isid_t * ocon, const char **name);

/**
 *  Get the context from an initial SID statement.
 *  @param policy The policy associated with the inital SID.
 *  @param ocon The initial SID from which to get the context.
 *  @param context Pointer in which to store the context.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *context will be NULL.
 */
	extern int qpol_isid_get_context(const qpol_policy_t * policy, const qpol_isid_t * ocon, const qpol_context_t ** context);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_ISID_QUERY_H */
