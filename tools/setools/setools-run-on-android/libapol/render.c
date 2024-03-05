/**
 * @file
 *
 * Routines to render various data structures used by libapol.
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

#include <config.h>

#include <apol/context-query.h>
#include <apol/policy.h>
#include <apol/render.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifndef WORDS_BIGENDIAN
extern void swab1(const void *from, void *to, ssize_t n);
#endif

/**
 * @brief Internal version of apol_ipv4_addr_render() version 4.1
 *
 * Implementation of the exported function apol_ipv4_addr_render()
 * for version 4.1; this symbol name is not exported.
 */
char *apol_ipv4_addr_render_new(const apol_policy_t * policydb, uint32_t addr[4])
{
	char buf[40], *b;
	unsigned char *p = (unsigned char *)&(addr[0]);
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	if ((b = strdup(buf)) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
	}
	return b;
}

char *apol_ipv4_addr_render(const apol_policy_t * policydb, uint32_t addr[4])
{
	return apol_ipv4_addr_render_new(policydb, addr);
}

/**
 * @brief Internal version of apol_ipv4_addr_render() version 4.0 or earlier
 * @deprecated use the 4.1 version.
 * @see apol_ipv4_addr_render()
 */
char *apol_ipv4_addr_render_old(apol_policy_t * policydb, uint32_t addr)
{
	char buf[40], *b;
	unsigned char *p = (unsigned char *)&addr;
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	if ((b = strdup(buf)) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
	}
	return b;
}

char *apol_ipv6_addr_render(const apol_policy_t * policydb, uint32_t addr[4])
{
	uint16_t tmp[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	int i, sz = 0, retv;
	char buf[40], *b;	       /* 8 * 4 hex digits + 7 * ':' + '\0' == max size of string */
	int contract = 0, prev_contr = 0, contr_idx_end = -1;
	for (i = 0; i < 4; i++) {
		uint32_t a;
#ifdef WORDS_BIGENDIAN
		a = addr[i];
#else
		swab1(addr + i, &a, sizeof(a));
#endif
		/* have to use division and mod here, so as to ignore
		 * host system's byte ordering */
		tmp[2 * i] = a % (1 << 16);
		tmp[2 * i + 1] = a / (1 << 16);
	}

	for (i = 0; i < 8; i++) {
		if (tmp[i] == 0) {
			contract++;
			if (i == 7 && contr_idx_end == -1)
				contr_idx_end = 8;
		} else {
			if (contract > prev_contr) {
				contr_idx_end = i;
			}
			prev_contr = contract;
			contract = 0;
		}
	}

	if (prev_contr > contract)
		contract = prev_contr;

	for (i = 0; i < 8; i++) {
		if (i == contr_idx_end - contract) {
			retv = snprintf(buf + sz, 40 - sz, i ? ":" : "::");
			sz += retv;
		} else if (i > contr_idx_end - contract && i < contr_idx_end) {
			continue;
		} else {
			retv = snprintf(buf + sz, 40 - sz, i == 7 ? "%04x" : "%04x:", tmp[i]);
			sz += retv;
		}
	}

	buf[sz] = '\0';
	if ((b = strdup(buf)) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
	}
	return b;
}

char *apol_qpol_context_render(const apol_policy_t * p, const qpol_context_t * context)
{
	apol_context_t *c = NULL;
	char *rendered_context;

	if (p == NULL || context == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}

	if ((c = apol_context_create_from_qpol_context(p, context)) == NULL) {
		return NULL;
	}
	rendered_context = apol_context_render(p, c);
	apol_context_destroy(&c);
	return rendered_context;
}
