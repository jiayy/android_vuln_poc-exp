/**
 * @file
 *
 * Provides a way for setools to make queries about portcons,
 * netifcons, and nodecons within a policy.  The caller obtains a
 * query object, fills in its parameters, and then runs the query; it
 * obtains a vector of results.  Searches are conjunctive -- all
 * fields of the search query must match for a datum to be added to
 * the results query.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006-2007 Tresys Technology, LLC
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

#include "policy-query-internal.h"
#include <apol/render.h>

#include <errno.h>
#include <string.h>

struct apol_portcon_query
{
	int proto;
	int low, high;
	apol_context_t *context;
	unsigned int flags;
};

struct apol_netifcon_query
{
	char *dev;
	apol_context_t *if_context, *msg_context;
	unsigned int if_flags, msg_flags;
};

struct apol_nodecon_query
{
	char proto, addr_proto, mask_proto;
	uint32_t addr[4], mask[4];
	apol_context_t *context;
	unsigned int flags;
};

/******************** portcon queries ********************/

int apol_portcon_get_by_query(const apol_policy_t * p, const apol_portcon_query_t * po, apol_vector_t ** v)
{
	qpol_iterator_t *iter;
	int retval = -1, retval2;
	*v = NULL;
	if (qpol_policy_get_portcon_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_portcon_t *portcon;
		if (qpol_iterator_get_item(iter, (void **)&portcon) < 0) {
			goto cleanup;
		}
		if (po != NULL) {
			uint16_t low, high;
			uint8_t proto;
			const qpol_context_t *context;
			if (qpol_portcon_get_low_port(p->p,
						      portcon, &low) < 0 ||
			    qpol_portcon_get_high_port(p->p,
						       portcon, &high) < 0 ||
			    qpol_portcon_get_protocol(p->p,
						      portcon, &proto) < 0 || qpol_portcon_get_context(p->p, portcon, &context) < 0)
			{
				goto cleanup;
			}
			if ((po->low >= 0 && ((uint16_t) po->low) != low) ||
			    (po->high >= 0 && ((uint16_t) po->high) != high) || (po->proto >= 0 && ((uint8_t) po->proto) != proto))
			{
				continue;
			}
			retval2 = apol_compare_context(p, context, po->context, po->flags);
			if (retval2 < 0) {
				goto cleanup;
			} else if (retval2 == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, portcon)) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	if (retval != 0) {
		apol_vector_destroy(v);
	}
	qpol_iterator_destroy(&iter);
	return retval;
}

apol_portcon_query_t *apol_portcon_query_create(void)
{
	apol_portcon_query_t *po = calloc(1, sizeof(*po));
	if (po == NULL) {
		return NULL;
	}
	po->proto = po->low = po->high = -1;
	return po;
}

void apol_portcon_query_destroy(apol_portcon_query_t ** po)
{
	if (*po != NULL) {
		apol_context_destroy(&((*po)->context));
		free(*po);
		*po = NULL;
	}
}

int apol_portcon_query_set_protocol(const apol_policy_t * p __attribute__ ((unused)), apol_portcon_query_t * po, int proto)
{
	po->proto = proto;
	return 0;
}

/**
 * @deprecated Use apol_portcon_query_set_protocol() instead.
 */
int apol_portcon_query_set_proto(apol_policy_t * p, apol_portcon_query_t * po, int proto)
{
	return apol_portcon_query_set_protocol(p, po, proto);
}
int apol_portcon_query_set_proto(apol_policy_t * p, apol_portcon_query_t * po, int proto) __attribute__ ((deprecated));

int apol_portcon_query_set_low(const apol_policy_t * p __attribute__ ((unused)), apol_portcon_query_t * po, int low)
{
	po->low = low;
	return 0;
}

int apol_portcon_query_set_high(const apol_policy_t * p __attribute__ ((unused)), apol_portcon_query_t * po, int high)
{
	po->high = high;
	return 0;
}

int apol_portcon_query_set_context(const apol_policy_t * p __attribute__ ((unused)),
				   apol_portcon_query_t * po, apol_context_t * context, unsigned int range_match)
{
	if (po->context != NULL) {
		apol_context_destroy(&po->context);
	}
	po->context = context;
	po->flags = (po->flags & ~APOL_QUERY_FLAGS) | range_match;
	return 0;
}

char *apol_portcon_render(const apol_policy_t * p, const qpol_portcon_t * portcon)
{
	char *line = NULL, *retval = NULL;
	char *buff = NULL;
	const char *proto_str = NULL;
	char *context_str = NULL;
	const qpol_context_t *ctxt = NULL;
	uint16_t low_port, high_port;
	uint8_t proto;

	const size_t bufflen = 50;     /* arbitrary size big enough to hold port no. */
	if (!portcon || !p)
		goto cleanup;

	buff = (char *)calloc(bufflen + 1, sizeof(char));
	if (!buff) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}

	if (qpol_portcon_get_protocol(p->p, portcon, &proto))
		goto cleanup;

	if ((proto_str = apol_protocol_to_str(proto)) == NULL) {
		ERR(p, "%s", "Could not get protocol string.");
		goto cleanup;
	}
	if (qpol_portcon_get_low_port(p->p, portcon, &low_port))
		goto cleanup;
	if (qpol_portcon_get_high_port(p->p, portcon, &high_port))
		goto cleanup;
	if (low_port == high_port)
		snprintf(buff, bufflen, "%d", low_port);
	else
		snprintf(buff, bufflen, "%d-%d", low_port, high_port);

	if (qpol_portcon_get_context(p->p, portcon, &ctxt))
		goto cleanup;
	context_str = apol_qpol_context_render(p, ctxt);
	if (!context_str)
		goto cleanup;

	line = (char *)calloc(4 + strlen("portcon") + strlen(proto_str) + strlen(buff) + strlen(context_str), sizeof(char));
	if (!line) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}

	sprintf(line, "portcon %s %s %s", proto_str, buff, context_str);

	retval = line;
      cleanup:
	free(buff);
	free(context_str);
	if (retval != line) {
		free(line);
	}
	return retval;
}

/******************** netifcon queries ********************/

int apol_netifcon_get_by_query(const apol_policy_t * p, const apol_netifcon_query_t * n, apol_vector_t ** v)
{
	qpol_iterator_t *iter;
	int retval = -1, retval2;
	*v = NULL;
	if (qpol_policy_get_netifcon_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		const qpol_netifcon_t *netifcon;
		if (qpol_iterator_get_item(iter, (void **)&netifcon) < 0) {
			goto cleanup;
		}
		if (n != NULL) {
			const char *name;
			const qpol_context_t *ifcon, *msgcon;
			if (qpol_netifcon_get_name(p->p, netifcon, &name) < 0 ||
			    qpol_netifcon_get_if_con(p->p, netifcon, &ifcon) < 0 ||
			    qpol_netifcon_get_msg_con(p->p, netifcon, &msgcon) < 0) {
				goto cleanup;
			}
			retval2 = apol_compare(p, name, n->dev, 0, NULL);
			if (retval2 < 0) {
				goto cleanup;
			} else if (retval2 == 0) {
				continue;
			}
			retval2 = apol_compare_context(p, ifcon, n->if_context, n->if_flags);
			if (retval2 < 0) {
				goto cleanup;
			} else if (retval2 == 0) {
				continue;
			}
			retval2 = apol_compare_context(p, msgcon, n->msg_context, n->msg_flags);
			if (retval2 < 0) {
				goto cleanup;
			} else if (retval2 == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, (void *)netifcon)) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	if (retval != 0) {
		apol_vector_destroy(v);
	}
	qpol_iterator_destroy(&iter);
	return retval;
}

apol_netifcon_query_t *apol_netifcon_query_create(void)
{
	return calloc(1, sizeof(apol_netifcon_query_t));
}

void apol_netifcon_query_destroy(apol_netifcon_query_t ** n)
{
	if (*n != NULL) {
		free((*n)->dev);
		apol_context_destroy(&((*n)->if_context));
		apol_context_destroy(&((*n)->msg_context));
		free(*n);
		*n = NULL;
	}
}

int apol_netifcon_query_set_device(const apol_policy_t * p, apol_netifcon_query_t * n, const char *dev)
{
	return apol_query_set(p, &n->dev, NULL, dev);
}

int apol_netifcon_query_set_if_context(const apol_policy_t * p __attribute__ ((unused)),
				       apol_netifcon_query_t * n, apol_context_t * context, unsigned int range_match)
{
	if (n->if_context != NULL) {
		apol_context_destroy(&n->if_context);
	}
	n->if_context = context;
	n->if_flags = (n->if_flags & ~APOL_QUERY_FLAGS) | range_match;
	return 0;
}

int apol_netifcon_query_set_msg_context(const apol_policy_t * p __attribute__ ((unused)),
					apol_netifcon_query_t * n, apol_context_t * context, unsigned int range_match)
{
	if (n->msg_context != NULL) {
		apol_context_destroy(&n->msg_context);
	}
	n->msg_context = context;
	n->msg_flags = (n->msg_flags & ~APOL_QUERY_FLAGS) | range_match;
	return 0;
}

char *apol_netifcon_render(const apol_policy_t * p, const qpol_netifcon_t * netifcon)
{
	char *line = NULL, *retval = NULL;
	char *devcon_str = NULL;
	char *pktcon_str = NULL;
	const char *iface_str = NULL;
	const qpol_context_t *ctxt = NULL;

	if (!netifcon || !p)
		goto cleanup;

	if (qpol_netifcon_get_if_con(p->p, netifcon, &ctxt))
		goto cleanup;
	devcon_str = apol_qpol_context_render(p, ctxt);
	if (!devcon_str)
		goto cleanup;

	if (qpol_netifcon_get_msg_con(p->p, netifcon, &ctxt))
		goto cleanup;
	pktcon_str = apol_qpol_context_render(p, ctxt);
	if (!pktcon_str) {
		goto cleanup;
	}

	if (qpol_netifcon_get_name(p->p, netifcon, &iface_str))
		return NULL;
	line = (char *)calloc(4 + strlen(iface_str) + strlen(devcon_str) + strlen(pktcon_str) + strlen("netifcon"), sizeof(char));
	if (!line) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	sprintf(line, "netifcon %s %s %s", iface_str, devcon_str, pktcon_str);

	retval = line;
      cleanup:
	free(devcon_str);
	free(pktcon_str);
	return retval;
}

/******************** nodecon queries ********************/

int apol_nodecon_get_by_query(const apol_policy_t * p, const apol_nodecon_query_t * n, apol_vector_t ** v)
{
	qpol_iterator_t *iter;
	int retval = -1, retval2;
	qpol_nodecon_t *nodecon = NULL;
	*v = NULL;
	if (qpol_policy_get_nodecon_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(free)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&nodecon) < 0) {
			goto cleanup;
		}
		if (n != NULL) {
			unsigned char proto, proto_a, proto_m;
			uint32_t *addr, *mask;
			const qpol_context_t *con;
			if (qpol_nodecon_get_protocol(p->p, nodecon, &proto) < 0 ||
			    qpol_nodecon_get_addr(p->p, nodecon, &addr, &proto_a) < 0 ||
			    qpol_nodecon_get_mask(p->p, nodecon, &mask, &proto_m) < 0 ||
			    qpol_nodecon_get_context(p->p, nodecon, &con) < 0) {
				goto cleanup;
			}
			if (n->proto >= 0 && n->proto != proto) {
				free(nodecon);
				continue;
			}
			if (n->addr_proto >= 0 &&
			    (n->addr_proto != proto_a ||
			     (proto_a == QPOL_IPV4 && memcmp(n->addr, addr, 1 * sizeof(uint32_t)) != 0) ||
			     (proto_a == QPOL_IPV6 && memcmp(n->addr, addr, 4 * sizeof(uint32_t)) != 0))) {
				free(nodecon);
				continue;
			}
			if (n->mask_proto >= 0 &&
			    (n->mask_proto != proto_m ||
			     (proto_m == QPOL_IPV4 && memcmp(n->mask, mask, 1 * sizeof(uint32_t)) != 0) ||
			     (proto_m == QPOL_IPV6 && memcmp(n->mask, mask, 4 * sizeof(uint32_t)) != 0))) {
				free(nodecon);
				continue;
			}
			retval2 = apol_compare_context(p, con, n->context, n->flags);
			if (retval2 < 0) {
				goto cleanup;
			} else if (retval2 == 0) {
				free(nodecon);
				continue;
			}
		}
		if (apol_vector_append(*v, nodecon)) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	if (retval != 0) {
		apol_vector_destroy(v);
		free(nodecon);
	}
	qpol_iterator_destroy(&iter);
	return retval;
}

apol_nodecon_query_t *apol_nodecon_query_create(void)
{
	apol_nodecon_query_t *n = calloc(1, sizeof(apol_nodecon_query_t));
	if (n != NULL) {
		n->proto = n->addr_proto = n->mask_proto = -1;
	}
	return n;
}

void apol_nodecon_query_destroy(apol_nodecon_query_t ** n)
{
	if (*n != NULL) {
		apol_context_destroy(&((*n)->context));
		free(*n);
		*n = NULL;
	}
}

int apol_nodecon_query_set_protocol(const apol_policy_t * p, apol_nodecon_query_t * n, int proto)
{
	if (proto == QPOL_IPV4 || proto == QPOL_IPV6) {
		n->proto = (char)proto;
	} else if (proto < 0) {
		n->proto = -1;
	} else {
		ERR(p, "Invalid protocol value %d.", proto);
		return -1;
	}
	return 0;
}

/**
 * @deprecated Use apol_nodecon_query_set_protocol() instead.
 */
int apol_nodecon_query_set_proto(apol_policy_t * p, apol_nodecon_query_t * n, int proto)
{
	return apol_nodecon_query_set_protocol(p, n, proto);
}
int apol_nodecon_query_set_proto(apol_policy_t * p, apol_nodecon_query_t * n, int proto) __attribute__ ((deprecated));

int apol_nodecon_query_set_addr(const apol_policy_t * p, apol_nodecon_query_t * n, uint32_t * addr, int proto)
{
	if (addr == NULL) {
		n->addr_proto = -1;
	} else {
		if (proto == QPOL_IPV4) {
			memcpy(n->addr, addr, 1 * sizeof(uint32_t));
		} else if (proto == QPOL_IPV6) {
			memcpy(n->addr, addr, 4 * sizeof(uint32_t));
		} else {
			ERR(p, "Invalid protocol value %d.", proto);
			return -1;
		}
		n->addr_proto = (char)proto;
	}
	return 0;
}

int apol_nodecon_query_set_mask(const apol_policy_t * p, apol_nodecon_query_t * n, uint32_t * mask, int proto)
{
	if (mask == NULL) {
		n->mask_proto = -1;
	} else {
		if (proto == QPOL_IPV4) {
			memcpy(n->mask, mask, 1 * sizeof(uint32_t));
		} else if (proto == QPOL_IPV6) {
			memcpy(n->mask, mask, 4 * sizeof(uint32_t));
		} else {
			ERR(p, "Invalid protocol value %d.", proto);
			return -1;
		}
		n->mask_proto = (char)proto;
	}
	return 0;
}

int apol_nodecon_query_set_context(const apol_policy_t * p __attribute__ ((unused)),
				   apol_nodecon_query_t * n, apol_context_t * context, unsigned int range_match)
{
	if (n->context != NULL) {
		apol_context_destroy(&n->context);
	}
	n->context = context;
	n->flags = (n->flags & ~APOL_QUERY_FLAGS) | range_match;
	return 0;
}

char *apol_nodecon_render(const apol_policy_t * p, const qpol_nodecon_t * nodecon)
{
	char *line = NULL, *retval = NULL;
	char *context_str = NULL;
	char *addr_str = NULL;
	char *mask_str = NULL;
	const qpol_context_t *ctxt = NULL;
	unsigned char protocol, addr_proto, mask_proto;
	uint32_t *addr = NULL, *mask = NULL;

	if (!nodecon || !p)
		goto cleanup;

	if (qpol_nodecon_get_protocol(p->p, nodecon, &protocol))
		goto cleanup;
	if (qpol_nodecon_get_addr(p->p, nodecon, &addr, &addr_proto))
		goto cleanup;
	if (qpol_nodecon_get_mask(p->p, nodecon, &mask, &mask_proto))
		goto cleanup;
	switch (protocol) {
	case QPOL_IPV4:
		if ((addr_str = apol_ipv4_addr_render(p, addr)) == NULL || (mask_str = apol_ipv4_addr_render(p, mask)) == NULL) {
			goto cleanup;
		}
		break;
	case QPOL_IPV6:
		if ((addr_str = apol_ipv6_addr_render(p, addr)) == NULL || (mask_str = apol_ipv6_addr_render(p, mask)) == NULL) {
			goto cleanup;
		}
		break;
	default:
		break;
	}

	if (qpol_nodecon_get_context(p->p, nodecon, &ctxt))
		goto cleanup;
	context_str = apol_qpol_context_render(p, ctxt);
	if (!context_str)
		goto cleanup;

	line = (char *)calloc(4 + strlen("nodecon") + strlen(addr_str) + strlen(mask_str) + strlen(context_str), sizeof(char));
	if (!line) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}

	sprintf(line, "nodecon %s %s %s", addr_str, mask_str, context_str);

	retval = line;
      cleanup:
	free(addr_str);
	free(mask_str);
	free(context_str);
	return retval;
}
