/**
 * @file
 *
 * Public interfaces that renders things that are not already covered
 * by one of the query files.  Unless otherwise stated, all functions
 * return a newly allocated string, which the caller is responsible
 * for free()ing afterwards.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 * @author David Windsor dwindsor@tresys.com
 *
 * Copyright (C) 2003-2007 Tresys Technology, LLC
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

#ifndef APOL_RENDER_H
#define APOL_RENDER_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "mls-query.h"
#include <qpol/policy.h>
#include <stdlib.h>

/**
 * Given an IPv4 address (or mask) in qpol byte order, allocate and
 * return a string representing that address.
 *
 * @param p Reference to a policy, for reporting errors
 * @param addr Address (or mask) to render.
 *
 * @return A newly allocated string, which the caller must free.
 * Returns NULL on error.
 */
	extern char *apol_ipv4_addr_render(const apol_policy_t * p, uint32_t addr[4]);

/**
 * Given an IPv6 address (or mask) in qpol byte order, allocate and
 * return a string representing that address.
 *
 * @param p Reference to a policy, for reporting errors
 * @param addr Address (or mask) to render.
 *
 * @return A newly allocated string, which the caller must free.
 * Returns NULL on error.
 */
	extern char *apol_ipv6_addr_render(const apol_policy_t * p, uint32_t addr[4]);

/**
 * Creates a string containing the textual representation of
 * a security context.
 * @param p Reference to a policy.
 * @param context Reference to the security context to be rendered.
 *
 * @return A newly allocated string on success, caller must free;
 * NULL on error.
 */
	extern char *apol_qpol_context_render(const apol_policy_t * p, const qpol_context_t * context);

#ifdef	__cplusplus
}
#endif

#endif
