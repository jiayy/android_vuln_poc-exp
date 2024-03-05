/**
 *  @file
 *  Defines the public interface for searching and iterating over portcon statements.
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

#ifndef QPOL_PORTCON_QUERY_H
#define QPOL_PORTCON_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>

	typedef struct qpol_portcon qpol_portcon_t;

/**
 *  Get a single portcon statement by port range and protocol.
 *  @param policy The policy from which to get the portcon statement.
 *  @param low The low port of the range of ports (or single port).
 *  @param high The high port of the range of ports; if searching for a
 *  single port, set high equal to low.
 *  @param protocol The protocol used in the portcon statement.
 *  Value should be one of IPPROTO_TCP or IPPROTO_UDP from netinet/in.h
 *  @param ocon Pointer in which to store the statement returned.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *ocon will be NULL.
 */
	extern int qpol_policy_get_portcon_by_port(const qpol_policy_t * policy, uint16_t low, uint16_t high, uint8_t protocol,
						   const qpol_portcon_t ** ocon);

/**
 *  Get an iterator for the portcon statements in a policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_portcon_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy 
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long 
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails, 
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_portcon_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter);

/**
 *  Get the protocol from a portcon statement.
 *  @param policy The policy associated with the portcon statement.
 *  @param ocon The portcon statement from which to get the protocol.
 *  @param protocol Pointer to set to the value of protocol.
 *  Value will be one of IPPROTO_TCP or IPPROTO_UDP from netinet/in.h
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *protocol will be 0;
 */
	extern int qpol_portcon_get_protocol(const qpol_policy_t * policy, const qpol_portcon_t * ocon, uint8_t * protocol);

/**
 *  Get the low port from a portcon statement.
 *  @param policy the policy associated with the portcon statement.
 *  @param ocon The portcon statement from which to get the low port.
 *  @param port Pointer to set to the port number.
 *  @return 0 on success < 0 on failure; if the call fails,
 *  errno will be set and *port will be 0.
 */
	extern int qpol_portcon_get_low_port(const qpol_policy_t * policy, const qpol_portcon_t * ocon, uint16_t * port);

/**
 *  Get the high port from a portcon statement.
 *  @param policy the policy associated with the portcon statement.
 *  @param ocon The portcon statement from which to get the high port.
 *  @param port Pointer to set to the port number.
 *  @return 0 on success < 0 on failure; if the call fails,
 *  errno will be set and *port will be 0.
 */
	extern int qpol_portcon_get_high_port(const qpol_policy_t * policy, const qpol_portcon_t * ocon, uint16_t * port);

/**
 *  Get the context from a portcon statement.
 *  @param policy the policy associated with the portcon statement.
 *  @param ocon The portcon statement from which to get the context.
 *  @param context Pointer in which to store the context.
 *  The caller should not free this pointer.
 *  @return 0 on success < 0 on failure; if the call fails,
 *  errno will be set and *context will be NULL.
 */
	extern int qpol_portcon_get_context(const qpol_policy_t * policy, const qpol_portcon_t * ocon,
					    const qpol_context_t ** context);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_PORTCON_QUERY_H */
