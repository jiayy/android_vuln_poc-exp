/**
 *  @file
 *  Implementation for querying aspects of a context.
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

#include "policy-query-internal.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <apol/render.h>

struct apol_context
{
	char *user, *role, *type;
	apol_mls_range_t *range;
};

apol_context_t *apol_context_create(void)
{
	return calloc(1, sizeof(apol_context_t));
}

apol_context_t *apol_context_create_from_qpol_context(const apol_policy_t * p, const qpol_context_t * context)
{
	apol_context_t *c = NULL;
	const qpol_user_t *user;
	const qpol_role_t *role;
	const qpol_type_t *type;
	const qpol_mls_range_t *range;
	const char *user_name, *role_name, *type_name;
	apol_mls_range_t *apol_range = NULL;
	if ((c = apol_context_create()) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto err;
	}
	if (qpol_context_get_user(p->p, context, &user) < 0 ||
	    qpol_context_get_role(p->p, context, &role) < 0 ||
	    qpol_context_get_type(p->p, context, &type) < 0 || qpol_context_get_range(p->p, context, &range) < 0) {
		goto err;
	}
	if (qpol_user_get_name(p->p, user, &user_name) < 0 ||
	    qpol_role_get_name(p->p, role, &role_name) < 0 || qpol_type_get_name(p->p, type, &type_name) < 0) {
		goto err;
	}
	if (qpol_policy_has_capability(p->p, QPOL_CAP_MLS)) {
		/* if the policy is MLS then convert the range, else
		 * rely upon the default value of NULL */
		if ((apol_range = apol_mls_range_create_from_qpol_mls_range(p, range)) == NULL) {
			goto err;
		}
	}
	if (apol_context_set_user(p, c, user_name) < 0 ||
	    apol_context_set_role(p, c, role_name) < 0 ||
	    apol_context_set_type(p, c, type_name) < 0 || apol_context_set_range(p, c, apol_range) < 0) {
		goto err;
	}
	return c;
      err:
	apol_mls_range_destroy(&apol_range);
	apol_context_destroy(&c);
	return NULL;
}

apol_context_t *apol_context_create_from_literal(const char *context_string)
{
	apol_context_t *c = NULL;
	bool is_context_compiled = false;
	regex_t context_regex;
	const size_t nmatch = 5;
	regmatch_t pmatch[nmatch];

	if ((c = apol_context_create()) == NULL) {
		goto err;
	}

	if (regcomp(&context_regex, "^([^:]*):([^:]*):([^:]*):?(.*)$", REG_EXTENDED) != 0) {
		goto err;
	}
	is_context_compiled = true;

	if (regexec(&context_regex, context_string, nmatch, pmatch, 0) != 0) {
		errno = EIO;
		goto err;
	}

	const char *s;
	size_t len;

	assert(pmatch[1].rm_so == 0);
	s = context_string + pmatch[1].rm_so;
	len = pmatch[1].rm_eo - pmatch[1].rm_so;	// no +1 to avoid copying colon
	if (len != 0 && *s != '*' && (c->user = strndup(s, len)) == NULL) {
		goto err;
	}

	assert(pmatch[2].rm_so != -1);
	s = context_string + pmatch[2].rm_so;
	len = pmatch[2].rm_eo - pmatch[2].rm_so;	// no +1 to avoid copying colon
	if (len != 0 && *s != '*' && (c->role = strndup(s, len)) == NULL) {
		goto err;
	}

	assert(pmatch[3].rm_so != -1);
	s = context_string + pmatch[3].rm_so;
	len = pmatch[3].rm_eo - pmatch[3].rm_so;	// no +1 to avoid copying colon
	if (len != 0 && *s != '*' && (c->type = strndup(s, len)) == NULL) {
		goto err;
	}

	if (pmatch[4].rm_so != -1) {
		s = context_string + pmatch[4].rm_so;
		len = pmatch[4].rm_eo - pmatch[4].rm_so;
		if (len != 0 && *s != '*' && (c->range = apol_mls_range_create_from_literal(s)) == NULL) {
			goto err;
		}
	}

	regfree(&context_regex);
	return c;

      err:
	apol_context_destroy(&c);
	if (is_context_compiled) {
		regfree(&context_regex);
	}
	return NULL;
}

void apol_context_destroy(apol_context_t ** context)
{
	if (*context != NULL) {
		free((*context)->user);
		free((*context)->role);
		free((*context)->type);
		apol_mls_range_destroy(&((*context)->range));
		free(*context);
		*context = NULL;
	}
}

int apol_context_set_user(const apol_policy_t * p, apol_context_t * context, const char *user)
{
	if (context == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (user != context->user) {
		free(context->user);
		context->user = NULL;
		if (user != NULL && (context->user = strdup(user)) == NULL) {
			ERR(p, "%s", strerror(errno));
			return -1;
		}
	}
	return 0;
}

int apol_context_set_role(const apol_policy_t * p, apol_context_t * context, const char *role)
{
	if (context == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (role != context->role) {
		free(context->role);
		context->role = NULL;
		if (role != NULL && (context->role = strdup(role)) == NULL) {
			ERR(p, "%s", strerror(errno));
			return -1;
		}
	}
	return 0;
}

int apol_context_set_type(const apol_policy_t * p, apol_context_t * context, const char *type)
{
	if (context == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (type != context->type) {
		free(context->type);
		context->type = NULL;
		if (type != NULL && (context->type = strdup(type)) == NULL) {
			ERR(p, "%s", strerror(errno));
			return -1;
		}
	}
	return 0;
}

int apol_context_set_range(const apol_policy_t * p, apol_context_t * context, apol_mls_range_t * range)
{
	if (context == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (range != context->range) {
		apol_mls_range_destroy(&(context->range));
		context->range = range;
	}
	return 0;
}

const char *apol_context_get_user(const apol_context_t * context)
{
	if (context == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return context->user;
}

const char *apol_context_get_role(const apol_context_t * context)
{
	if (context == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return context->role;
}

const char *apol_context_get_type(const apol_context_t * context)
{
	if (context == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return context->type;
}

const apol_mls_range_t *apol_context_get_range(const apol_context_t * context)
{
	if (context == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return context->range;
}

int apol_context_compare(const apol_policy_t * p, const apol_context_t * target, const apol_context_t * search,
			 unsigned int range_compare_type)
{
	uint32_t value0, value1;
	if (p == NULL || target == NULL || search == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (target->user != NULL && search->user != NULL) {
		const qpol_user_t *user0, *user1;
		if (qpol_policy_get_user_by_name(p->p,
						 target->user, &user0) < 0 ||
		    qpol_policy_get_user_by_name(p->p,
						 search->user, &user1) < 0 ||
		    qpol_user_get_value(p->p, user0, &value0) < 0 || qpol_user_get_value(p->p, user1, &value1) < 0) {
			return -1;
		}
		if (value0 != value1) {
			return 0;
		}
	}
	if (target->role != NULL && search->role != NULL) {
		const qpol_role_t *role0, *role1;
		if (qpol_policy_get_role_by_name(p->p,
						 target->role, &role0) < 0 ||
		    qpol_policy_get_role_by_name(p->p,
						 search->role, &role1) < 0 ||
		    qpol_role_get_value(p->p, role0, &value0) < 0 || qpol_role_get_value(p->p, role1, &value1) < 0) {
			return -1;
		}
		if (value0 != value1) {
			return 0;
		}
	}
	if (target->type != NULL && search->type != NULL) {
		const qpol_type_t *type0, *type1;
		if (qpol_policy_get_type_by_name(p->p,
						 target->type, &type0) < 0 ||
		    qpol_policy_get_type_by_name(p->p,
						 search->type, &type1) < 0 ||
		    qpol_type_get_value(p->p, type0, &value0) < 0 || qpol_type_get_value(p->p, type1, &value1) < 0) {
			return -1;
		}
		if (value0 != value1) {
			return 0;
		}
	}
	if (target->range != NULL && search->range != NULL) {
		return apol_mls_range_compare(p, target->range, search->range, range_compare_type);
	}
	return 1;
}

int apol_context_validate(const apol_policy_t * p, const apol_context_t * context)
{
	if (context == NULL ||
	    context->user == NULL ||
	    context->role == NULL || context->type == NULL || (apol_policy_is_mls(p) && context->range == NULL)) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	return apol_context_validate_partial(p, context);
}

int apol_context_validate_partial(const apol_policy_t * p, const apol_context_t * context)
{
	apol_user_query_t *user_query = NULL;
	apol_role_query_t *role_query = NULL;
	apol_vector_t *user_v = NULL, *role_v = NULL;
	const qpol_user_t *user;
	const qpol_type_t *type;
	const qpol_mls_range_t *user_range;
	apol_mls_range_t *user_apol_range = NULL;
	int retval = -1, retval2;

	if (context == NULL) {
		return 1;
	}
	if (context->user != NULL) {
		if ((user_query = apol_user_query_create()) == NULL) {
			ERR(p, "%s", strerror(ENOMEM));
		}
		if (apol_user_query_set_user(p, user_query, context->user) < 0 ||
		    (context->role != NULL && apol_user_query_set_role(p, user_query, context->role) < 0) ||
		    apol_user_get_by_query(p, user_query, &user_v) < 0) {
			goto cleanup;
		}
		if (apol_vector_get_size(user_v) == 0) {
			retval = 0;
			goto cleanup;
		}
	}
	if (context->role != NULL) {
		if ((role_query = apol_role_query_create()) == NULL) {
			ERR(p, "%s", strerror(ENOMEM));
		}
		if (apol_role_query_set_role(p, role_query, context->role) < 0 ||
		    (context->type != NULL && apol_role_query_set_type(p, role_query, context->type) < 0) ||
		    apol_role_get_by_query(p, role_query, &role_v) < 0) {
			goto cleanup;
		}
		if (apol_vector_get_size(role_v) == 0) {
			retval = 0;
			goto cleanup;
		}
	}
	if (context->type != NULL) {
		if (qpol_policy_get_type_by_name(p->p, context->type, &type) < 0) {
			retval = 0;
			goto cleanup;
		}
	}
	if (apol_policy_is_mls(p) && context->range != NULL) {
		retval2 = apol_mls_range_validate(p, context->range);
		if (retval2 != 1) {
			retval = retval2;
			goto cleanup;
		}
		/* next check that the user has access to this context */
		if (context->user != NULL) {
			if (qpol_policy_get_user_by_name(p->p, context->user, &user) < 0 ||
			    qpol_user_get_range(p->p, user, &user_range) < 0) {
				goto cleanup;
			}
			user_apol_range = apol_mls_range_create_from_qpol_mls_range(p, user_range);
			if (user_apol_range == NULL) {
				ERR(p, "%s", strerror(ENOMEM));
				goto cleanup;
			}
			retval2 = apol_mls_range_compare(p, user_apol_range, context->range, APOL_QUERY_SUB);
			if (retval2 != 1) {
				retval = retval2;
				goto cleanup;
			}
		}
	}
	retval = 1;
      cleanup:
	apol_user_query_destroy(&user_query);
	apol_role_query_destroy(&role_query);
	apol_vector_destroy(&user_v);
	apol_vector_destroy(&role_v);
	apol_mls_range_destroy(&user_apol_range);
	return retval;
}

char *apol_context_render(const apol_policy_t * p, const apol_context_t * context)
{
	char *buf = NULL, *range_str = NULL;
	size_t buf_sz = 0;

	if (context == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	if (p == NULL && !apol_mls_range_is_literal(context->range)) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	if (apol_str_appendf(&buf, &buf_sz, "%s:", (context->user != NULL ? context->user : "*")) != 0) {
		ERR(p, "%s", strerror(errno));
		goto err_return;
	}
	if (apol_str_appendf(&buf, &buf_sz, "%s:", (context->role != NULL ? context->role : "*")) != 0) {
		ERR(p, "%s", strerror(errno));
		goto err_return;
	}
	if (apol_str_append(&buf, &buf_sz, (context->type != NULL ? context->type : "*")) != 0) {
		ERR(p, "%s", strerror(errno));
		goto err_return;
	}
	if ((p != NULL && apol_policy_is_mls(p)) || (p == NULL)) {
		if (context->range == NULL) {
			range_str = strdup("*");
		} else {
			range_str = apol_mls_range_render(p, context->range);
		}
		if (range_str == NULL) {
			goto err_return;
		}
		if (apol_str_appendf(&buf, &buf_sz, ":%s", range_str) != 0) {
			ERR(p, "%s", strerror(errno));
			goto err_return;
		}
		free(range_str);
	}
	return buf;

      err_return:
	free(buf);
	free(range_str);
	return NULL;
}

int apol_context_convert(const apol_policy_t * p, apol_context_t * context)
{
	if (p == NULL || context == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (context->range != NULL) {
		return apol_mls_range_convert(p, context->range);
	}
	return 0;
}
