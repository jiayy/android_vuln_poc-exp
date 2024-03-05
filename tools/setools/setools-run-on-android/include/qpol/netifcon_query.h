/**
 *  @file
 *  Defines the public interface for searching and iterating over netifcon statements.
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

#ifndef QPOL_NETIFCON_QUERY_H
#define QPOL_NETIFCON_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>

	typedef struct qpol_netifcon qpol_netifcon_t;

/**
 *  Get a netifcon statement by interface name.
 *  @param policy The policy from which to get the netifcon statement.
 *  @param name The name of the interface.
 *  @param ocon Pointer in which to store the statement returned.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *ocon will be NULL.
 */
	extern int qpol_policy_get_netifcon_by_name(const qpol_policy_t * policy, const char *name, const qpol_netifcon_t ** ocon);

/**
 *  Get an iterator for the netifcon statements in a policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_netifcon_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy 
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long 
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails, 
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_netifcon_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter);

/**
 *  Get the name of the interface from a netifcon statement.
 *  @param policy The policy associated wiht the netifcon statement.
 *  @param ocon The netifcon statement from which to get the name.
 *  @param name Pointer in which to store the interface name. The caller
 *  should not free this string.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *name will be NULL.
 */
	extern int qpol_netifcon_get_name(const qpol_policy_t * policy, const qpol_netifcon_t * ocon, const char **name);

/**
 *  Get the message context from a netifcon statement.
 *  @param policy The policy associated with the netifcon statement.
 *  @param ocon The netifcon statement from which to get the message context.
 *  @parma context Pointer in which to store the context.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *context will be NULL.
 */
	extern int qpol_netifcon_get_msg_con(const qpol_policy_t * policy, const qpol_netifcon_t * ocon,
					     const qpol_context_t ** context);

/**
 *  Get the interface context from a netifcon statement.
 *  @param policy The policy associated with the netifcon statement.
 *  @param ocon The netifcon statement from which to get the interface context.
 *  @parma context Pointer in which to store the context.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *context will be NULL.
 */
	extern int qpol_netifcon_get_if_con(const qpol_policy_t * policy, const qpol_netifcon_t * ocon,
					    const qpol_context_t ** context);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_NETIFCON_QUERY_H */
