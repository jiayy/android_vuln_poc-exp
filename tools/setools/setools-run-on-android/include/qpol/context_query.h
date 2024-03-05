/**
 *  @file
 *  Defines the public interface accessing contexts.
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

#ifndef QPOL_CONTEXT_QUERY_H
#define QPOL_CONTEXT_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>
#include <qpol/policy.h>
#include <qpol/user_query.h>
#include <qpol/role_query.h>
#include <qpol/type_query.h>
#include <qpol/mls_query.h>

	typedef struct qpol_context qpol_context_t;

/**
 *  Get the datum for the user field of a context.
 *  @param policy The policy associated with the context.
 *  @param context The context from which to get the user.
 *  @param user Pointer in which to store the user datum.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *user will be NULL.
 */
	extern int qpol_context_get_user(const qpol_policy_t * policy, const qpol_context_t * context, const qpol_user_t ** user);

/**
 *  Get the datum for the role field of a context.
 *  @param policy The policy associated with the context.
 *  @param context The context from which to get the role.
 *  @param role Pointer in which to store the role datum.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *role will be NULL.
 */
	extern int qpol_context_get_role(const qpol_policy_t * policy, const qpol_context_t * context, const qpol_role_t ** role);

/**
 *  Get the datum for the type field of a context.
 *  @param policy The policy associated with the context.
 *  @param context The context from which to get the type.
 *  @param type Pointer in which to store the type datum.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *type will be NULL.
 */
	extern int qpol_context_get_type(const qpol_policy_t * policy, const qpol_context_t * context, const qpol_type_t ** type);

/**
 *  Get the datum for the MLS range field of a context.
 *  @param policy The policy associated with the context.
 *  @param context The context from which to get the MLS range.
 *  @param range Pointer in which to store the MLS range.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *range will be NULL.
 */
	extern int qpol_context_get_range(const qpol_policy_t * policy, const qpol_context_t * context,
					  const qpol_mls_range_t ** range);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_CONTEXT_QUERY_H */
