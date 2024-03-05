/**
 *  @file
 *  Public Interface for querying portcons, netifcons, and nodecons of
 *  a policy.
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

#ifndef APOL_NETCON_QUERY_H
#define APOL_NETCON_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include "context-query.h"
#include <qpol/policy.h>

	typedef struct apol_portcon_query apol_portcon_query_t;
	typedef struct apol_netifcon_query apol_netifcon_query_t;
	typedef struct apol_nodecon_query apol_nodecon_query_t;

/******************** portcon queries ********************/

/**
 * Execute a query against all portcons within the policy.  The
 * returned portcons will be unordered.
 *
 * @param p Policy within which to look up portcons.
 * @param po Structure containing parameters for query.	 If this is
 * NULL then return all portcons.
 * @param v Reference to a vector of qpol_portcon_t.  The vector will
 * be allocated by this function. The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_portcon_get_by_query(const apol_policy_t * p, const apol_portcon_query_t * po, apol_vector_t ** v);

/**
 * Allocate and return a new portcon query structure. All fields are
 * initialized, such that running this blank query results in
 * returning all portcons within the policy. The caller must call
 * apol_portcon_query_destroy() upon the return value afterwards.
 *
 * @return An initialized portcon query structure, or NULL upon error.
 */
	extern apol_portcon_query_t *apol_portcon_query_create(void);

/**
 * Deallocate all memory associated with the referenced portcon
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param po Reference to a portcon query structure to destroy.
 */
	extern void apol_portcon_query_destroy(apol_portcon_query_t ** po);

/**
 * Set a portcon query to return only portcons that use this protocol.
 *
 * @param p Policy handler, to report errors.
 * @param po Portcon query to set.
 * @param proto Limit query to only portcons with this protocol, or
 * negative to unset this field.
 *
 * @return Always 0.
 */
	extern int apol_portcon_query_set_protocol(const apol_policy_t * p, apol_portcon_query_t * po, int proto);

/**
 * Set a portcon query to return only portcons with this as their low
 * port.
 *
 * @param p Policy handler, to report errors.
 * @param po Portcon query to set.
 * @param low Limit query to only portcons with this low port, or
 * negative to unset this field.
 *
 * @return Always 0.
 */
	extern int apol_portcon_query_set_low(const apol_policy_t * p, apol_portcon_query_t * po, int low);

/**
 * Set a portcon query to return only portcons with this as their high
 * port.
 *
 * @param p Policy handler, to report errors.
 * @param po Portcon query to set.
 * @param high Limit query to only portcons with this high port, or
 * negative to unset this field.
 *
 * @return Always 0.
 */
	extern int apol_portcon_query_set_high(const apol_policy_t * p, apol_portcon_query_t * po, int high);

/**
 * Set a portcon query to return only portcons matching a context.
 * This function takes ownership of the context, such that the caller
 * must not modify nor destroy it afterwards.
 *
 * @param p Policy handler, to report errors.
 * @param po Portcon query to set.
 * @param context Limit query to only portcons matching this context,
 * or NULL to unset this field.
 * @param range_match Specifies how to match the MLS range within the
 * context.  This must be one of APOL_QUERY_SUB, APOL_QUERY_SUPER, or
 * APOL_QUERY_EXACT.  This parameter is ignored if context is NULL.
 *
 * @return Always returns 0.
 */
	extern int apol_portcon_query_set_context(const apol_policy_t * p,
						  apol_portcon_query_t * po, apol_context_t * context, unsigned int range_match);

/**
 * Creates a string containing the textual representation of
 * a portcon type.
 * @param p Reference to a policy.
 * @param portcon Reference to the portcon statement to be rendered.
 *
 * @return A newly allocated string on success, caller must free;
 * NULL on error.
 */
	extern char *apol_portcon_render(const apol_policy_t * p, const qpol_portcon_t * portcon);

/******************** netifcon queries ********************/

/**
 * Execute a query against all netifcons within the policy.  The
 * returned netifcons will be unordered.
 *
 * @param p Policy within which to look up netifcons.
 * @param n Structure containing parameters for query.	If this is
 * NULL then return all netifcons.
 * @param v Reference to a vector of qpol_netifcon_t.  The vector will
 * be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards,.  This will be set to NULL upon
 * no results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_netifcon_get_by_query(const apol_policy_t * p, const apol_netifcon_query_t * n, apol_vector_t ** v);

/**
 * Allocate and return a new netifcon query structure.	All fields are
 * initialized, such that running this blank query results in
 * returning all netifcons within the policy.  The caller must call
 * apol_netifcon_query_destroy() upon the return value afterwards.
 *
 * @return An initialized netifcon query structure, or NULL upon
 * error.
 */
	extern apol_netifcon_query_t *apol_netifcon_query_create(void);

/**
 * Deallocate all memory associated with the referenced netifcon
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param n Reference to a netifcon query structure to destroy.
 */
	extern void apol_netifcon_query_destroy(apol_netifcon_query_t ** n);

/**
 * Set a netifcon query to return only netifcons that use this device.
 *
 * @param p Policy handler, to report errors.
 * @param n Netifcon query to set.
 * @param dev Limit query to only netifcons that use this device, or
 * NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_netifcon_query_set_device(const apol_policy_t * p, apol_netifcon_query_t * n, const char *dev);

/**
 * Set a netifcon query to return only netifcons matching this context
 * for its interface.  This function takes ownership of the context,
 * such that the caller must not modify nor destroy it afterwards.
 *
 * @param p Policy handler, to report errors.
 * @param n Netifcon query to set.
 * @param context Limit query to only netifcon matching this context
 * for its interface, or NULL to unset this field.
 * @param range_match Specifies how to match the MLS range within the
 * context.  This must be one of APOL_QUERY_SUB, APOL_QUERY_SUPER, or
 * APOL_QUERY_EXACT.  This parameter is ignored if context is NULL.
 *
 * @return Always returns 0.
 */
	extern int apol_netifcon_query_set_if_context(const apol_policy_t * p,
						      apol_netifcon_query_t * n, apol_context_t * context,
						      unsigned int range_match);

/**
 * Set a netifcon query to return only netifcons matching this context
 * for its messages.  This function takes ownership of the context,
 * such that the caller must not modify nor destroy it afterwards.
 *
 * @param p Policy handler, to report errors.
 * @param n Netifcon query to set.
 * @param context Limit query to only netifcon matching this context
 * for its messages, or NULL to unset this field.
 * @param range_match Specifies how to match the MLS range within the
 * context.  This must be one of APOL_QUERY_SUB, APOL_QUERY_SUPER, or
 * APOL_QUERY_EXACT.  This parameter is ignored if context is NULL.
 *
 * @return Always returns 0.
 */
	extern int apol_netifcon_query_set_msg_context(const apol_policy_t * p,
						       apol_netifcon_query_t * n, apol_context_t * context,
						       unsigned int range_match);

/**
 * Creates a string containing the textual representation of
 * a netifcon type.
 * @param p Reference to a policy.
 * @param netifcon Reference to the netifcon statement to be rendered.
 *
 * @return A newly allocated string on success, caller must free;
 * NULL on error.
 */
	extern char *apol_netifcon_render(const apol_policy_t * p, const qpol_netifcon_t * netifcon);

/******************** nodecon queries ********************/

/**
 * Execute a query against all nodecons within the policy.  The
 * returned nodecons will be unordered.
 *
 * @param p Policy within which to look up nodecons.
 * @param n Structure containing parameters for query.	If this is
 * NULL then return all nodecons.
 * @param v Reference to a vector of qpol_nodecon_t.  The vector will
 * be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_nodecon_get_by_query(const apol_policy_t * p, const apol_nodecon_query_t * n, apol_vector_t ** v);

/**
 * Allocate and return a new nodecon query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all nodecons within the policy.  The caller must call
 * apol_nodecon_query_destroy() upon the return value afterwards.
 *
 * @return An initialized nodecon query structure, or NULL upon
 * error.
 */
	extern apol_nodecon_query_t *apol_nodecon_query_create(void);

/**
 * Deallocate all memory associated with the referenced nodecon
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param n Reference to a nodecon query structure to destroy.
 */
	extern void apol_nodecon_query_destroy(apol_nodecon_query_t ** n);

/**
 * Set a nodecon query to return only nodecons with this protocol,
 * either IPv4 or IPv6.
 *
 * @param p Policy handler, to report errors.
 * @param n Nodecon query to set.
 * @param proto Limit query to only this protocol, either QPOL_IPV4 or
 * QPOL_IPV6, or a negative value to unset this field.
 *
 * @return 0 if protocol was valid, -1 on error.
 */
	extern int apol_nodecon_query_set_protocol(const apol_policy_t * p, apol_nodecon_query_t * n, int proto);

/**
 * Set a nodecon query to return only nodecons with this address.  If
 * the protocol is QPOL_IPV4 then only the first element of the
 * address array is used, for QPOL_IPV6 all four are used.
 *
 * @param p Policy handler, to report errors.
 * @param n Nodecon query to set.
 * @param addr Array of no more than four elements representing the
 * address, or NULL to unset this field.  This function will make a
 * copy of the array.
 * @param proto Format of address, either QPOL_IPV4 or QPOL_IPV6.
 * This parameter is ignored if addr is NULL.
 *
 * @return 0 if protocol was valid, -1 on error.
 */
	extern int apol_nodecon_query_set_addr(const apol_policy_t * p, apol_nodecon_query_t * n, uint32_t * addr, int proto);

/**
 * Set a nodecon query to return only nodecons with this netmask.  If
 * the protocol is QPOL_IPV4 then only the first element of the mask
 * array is used, for QPOL_IPV6 all four are used.
 *
 * @param p Policy handler, to report errors.
 * @param n Nodecon query to set.
 * @param mask Array of no more than four elements representing the
 * netmask, or NULL to unset this field.  This function will make a
 * copy of the array.
 * @param proto Format of mask, either QPOL_IPV4 or QPOL_IPV6.  This
 * parameter is ignored if mask is NULL.
 *
 * @return 0 if protocol was valid, -1 on error.
 */
	extern int apol_nodecon_query_set_mask(const apol_policy_t * p, apol_nodecon_query_t * n, uint32_t * mask, int proto);

/**
 * Set a nodecon query to return only nodecons matching this context.
 * This function takes ownership of the context, such that the caller
 * must not modify nor destroy it afterwards.
 *
 * @param p Policy handler, to report errors.
 * @param n Nodecon query to set.
 * @param context Limit query to only nodecons matching this context,
 * or NULL to unset this field.
 * @param range_match Specifies how to match the MLS range within the
 * context.  This must be one of APOL_QUERY_SUB, APOL_QUERY_SUPER, or
 * APOL_QUERY_EXACT.  This parameter is ignored if context is NULL.
 *
 * @return Always returns 0.
 */
	extern int apol_nodecon_query_set_context(const apol_policy_t * p,
						  apol_nodecon_query_t * n, apol_context_t * context, unsigned int range_match);

/**
 * Creates a string containing the textual representation of
 * a nodecon type.
 * @param p Reference to a policy.
 * @param nodecon Reference to the nodecon statement to be rendered.
 *
 * @return A newly allocated string on success, caller must free;
 * NULL on error.
 */
	extern char *apol_nodecon_render(const apol_policy_t * p, const qpol_nodecon_t * nodecon);

#ifdef	__cplusplus
}
#endif

#endif				       /* APOL_NETCON_QUERY_H */
