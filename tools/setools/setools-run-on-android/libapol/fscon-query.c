/**
 * @file
 *
 * Provides a way for setools to make queries about genfscons and
 * fs_use statements within a policy.  The caller obtains a query
 * object, fills in its parameters, and then runs the query; it
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
#include <stdio.h>
#include <stdbool.h>

struct apol_genfscon_query
{
	char *fs, *path;
	uint32_t objclass;
	bool objclass_set;
	apol_context_t *context;
	unsigned int flags;
};

struct apol_fs_use_query
{
	char *fs;
	uint32_t behavior;
	bool behavior_set;
	apol_context_t *context;
	unsigned int flags;
};

/******************** genfscon queries ********************/

int apol_genfscon_get_by_query(const apol_policy_t * p, const apol_genfscon_query_t * g, apol_vector_t ** v)
{
	qpol_iterator_t *iter;
	int retval = -1, retval2;
	qpol_genfscon_t *genfscon = NULL;
	*v = NULL;
	if (qpol_policy_get_genfscon_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(free)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&genfscon) < 0) {
			goto cleanup;
		}
		if (g != NULL) {
			const char *fs, *path;
			uint32_t objclass;
			const qpol_context_t *context;
			if (qpol_genfscon_get_name(p->p, genfscon, &fs) < 0 ||
			    qpol_genfscon_get_path(p->p, genfscon, &path) < 0 ||
			    qpol_genfscon_get_class(p->p, genfscon, &objclass) < 0 ||
			    qpol_genfscon_get_context(p->p, genfscon, &context) < 0) {
				goto cleanup;
			}
			retval2 = apol_compare(p, fs, g->fs, 0, NULL);
			if (retval2 < 0) {
				goto cleanup;
			} else if (retval2 == 0) {
				free(genfscon);
				continue;
			}
			retval2 = apol_compare(p, path, g->path, 0, NULL);
			if (retval2 < 0) {
				goto cleanup;
			} else if (retval2 == 0) {
				free(genfscon);
				continue;
			}
			if (g->objclass_set && g->objclass != objclass) {
				free(genfscon);
				continue;
			}
			retval2 = apol_compare_context(p, context, g->context, g->flags);
			if (retval2 < 0) {
				goto cleanup;
			} else if (retval2 == 0) {
				free(genfscon);
				continue;
			}
		}
		if (apol_vector_append(*v, genfscon)) {
			ERR(p, "%s", strerror(EINVAL));
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	if (retval != 0) {
		apol_vector_destroy(v);
		free(genfscon);
	}
	qpol_iterator_destroy(&iter);
	return retval;
}

apol_genfscon_query_t *apol_genfscon_query_create(void)
{
	apol_genfscon_query_t *g = calloc(1, sizeof(apol_genfscon_query_t));
	if (g != NULL) {
		g->objclass = -1;
	}
	return g;
}

void apol_genfscon_query_destroy(apol_genfscon_query_t ** g)
{
	if (*g != NULL) {
		free((*g)->fs);
		free((*g)->path);
		apol_context_destroy(&((*g)->context));
		free(*g);
		*g = NULL;
	}
}

int apol_genfscon_query_set_filesystem(const apol_policy_t * p, apol_genfscon_query_t * g, const char *fs)
{
	return apol_query_set(p, &g->fs, NULL, fs);
}

int apol_genfscon_query_set_path(const apol_policy_t * p, apol_genfscon_query_t * g, const char *path)
{
	int tmp = apol_query_set(p, &g->path, NULL, path);
	if (!tmp && g->path) {
		if (strlen(g->path) > 1 && g->path[strlen(g->path) - 1] == '/')
			g->path[strlen(g->path) - 1] = 0;
	}
	return tmp;
}

int apol_genfscon_query_set_objclass(const apol_policy_t * p, apol_genfscon_query_t * g, int objclass)
{
	if (objclass < 0) {
		g->objclass = 0;
		g->objclass_set = false;
	} else {
		switch (objclass) {
		case QPOL_CLASS_BLK_FILE:
		case QPOL_CLASS_CHR_FILE:
		case QPOL_CLASS_DIR:
		case QPOL_CLASS_FIFO_FILE:
		case QPOL_CLASS_FILE:
		case QPOL_CLASS_LNK_FILE:
		case QPOL_CLASS_SOCK_FILE:
		case QPOL_CLASS_ALL:
		{
			g->objclass = objclass;
			g->objclass_set = true;
			break;
		}
		default:
			ERR(p, "%s", "Invalid object class given.");
			return -1;
		}
	}
	return 0;
}

int apol_genfscon_query_set_context(const apol_policy_t * p __attribute__ ((unused)),
				    apol_genfscon_query_t * g, apol_context_t * context, unsigned int range_match)
{
	if (g->context != NULL) {
		apol_context_destroy(&g->context);
	}
	g->context = context;
	g->flags = (g->flags & ~APOL_QUERY_FLAGS) | range_match;
	return 0;
}

char *apol_genfscon_render(const apol_policy_t * p, const qpol_genfscon_t * genfscon)
{
	char *line = NULL, *retval = NULL;
	const qpol_context_t *ctxt = NULL;
	char *context_str = NULL;
	const char *type_str = NULL;
	const char *name = NULL, *path = NULL;
	uint32_t fclass;

	if (!genfscon || !p)
		goto cleanup;

	if (qpol_genfscon_get_name(p->p, genfscon, &name))
		goto cleanup;
	if (qpol_genfscon_get_path(p->p, genfscon, &path))
		goto cleanup;
	if (qpol_genfscon_get_class(p->p, genfscon, &fclass))
		return NULL;
	if (qpol_genfscon_get_context(p->p, genfscon, &ctxt))
		goto cleanup;

	switch (fclass) {
	case QPOL_CLASS_DIR:
		type_str = " -d ";
		break;
	case QPOL_CLASS_CHR_FILE:
		type_str = " -c ";
		break;
	case QPOL_CLASS_BLK_FILE:
		type_str = " -b ";
		break;
	case QPOL_CLASS_FILE:
		type_str = " -- ";
		break;
	case QPOL_CLASS_FIFO_FILE:
		type_str = " -p ";
		break;
	case QPOL_CLASS_LNK_FILE:
		type_str = " -l ";
		break;
	case QPOL_CLASS_SOCK_FILE:
		type_str = " -s ";
		break;
	case QPOL_CLASS_ALL:
		type_str = "    ";
		break;
	default:
		goto cleanup;
		break;
	}
	context_str = apol_qpol_context_render(p, ctxt);
	if (!context_str)
		goto cleanup;

	if (asprintf(&line, "genfscon %s %s %s %s", name, path, type_str, context_str) < 0) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	retval = line;
      cleanup:
	free(context_str);
	if (retval != line) {
		free(line);
	}
	return retval;
}

/******************** fs_use queries ********************/

int apol_fs_use_get_by_query(const apol_policy_t * p, const apol_fs_use_query_t * f, apol_vector_t ** v)
{
	qpol_iterator_t *iter;
	int retval = -1, retval2;
	const qpol_fs_use_t *fs_use = NULL;
	*v = NULL;
	if (qpol_policy_get_fs_use_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&fs_use) < 0) {
			goto cleanup;
		}
		if (f != NULL) {
			const char *fs;
			uint32_t behavior;
			const qpol_context_t *context = NULL;
			if (qpol_fs_use_get_name(p->p, fs_use, &fs) < 0 || qpol_fs_use_get_behavior(p->p, fs_use, &behavior) < 0) {
				goto cleanup;
			}
			if (behavior != QPOL_FS_USE_PSID && qpol_fs_use_get_context(p->p, fs_use, &context) < 0) {
				goto cleanup;
			}
			retval2 = apol_compare(p, fs, f->fs, 0, NULL);
			if (retval2 < 0) {
				goto cleanup;
			} else if (retval2 == 0) {
				continue;
			}
			if (f->behavior_set && f->behavior != behavior) {
				continue;
			}
			/* recall that fs_use_psid statements do not
			 * have contexts */
			if (f->context != NULL && behavior == QPOL_FS_USE_PSID) {
				retval2 = 0;
			} else {
				retval2 = apol_compare_context(p, context, f->context, f->flags);
				if (retval2 < 0) {
					goto cleanup;
				}
			}
			if (retval2 == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, (void *)fs_use)) {
			ERR(p, "%s", strerror(EINVAL));
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

apol_fs_use_query_t *apol_fs_use_query_create(void)
{
	apol_fs_use_query_t *f = calloc(1, sizeof(apol_fs_use_query_t));
	if (f != NULL) {
		f->behavior = -1;
	}
	return f;
}

void apol_fs_use_query_destroy(apol_fs_use_query_t ** f)
{
	if (*f != NULL) {
		free((*f)->fs);
		apol_context_destroy(&((*f)->context));
		free(*f);
		*f = NULL;
	}
}

int apol_fs_use_query_set_filesystem(const apol_policy_t * p, apol_fs_use_query_t * f, const char *fs)
{
	return apol_query_set(p, &f->fs, NULL, fs);
}

int apol_fs_use_query_set_behavior(const apol_policy_t * p, apol_fs_use_query_t * f, int behavior)
{
	if (behavior < 0) {
		f->behavior = 0;
		f->behavior_set = false;
	} else {
		switch (behavior) {
		case QPOL_FS_USE_XATTR:
		case QPOL_FS_USE_TASK:
		case QPOL_FS_USE_TRANS:
		case QPOL_FS_USE_GENFS:
		case QPOL_FS_USE_NONE:
		case QPOL_FS_USE_PSID:
		{
			f->behavior = behavior;
			f->behavior_set = true;
			break;
		}
		default:
			ERR(p, "%s", "Invalid fs_use behavior given.");
			return -1;
		}
	}
	return 0;
}

int apol_fs_use_query_set_context(const apol_policy_t * p __attribute__ ((unused)),
				  apol_fs_use_query_t * f, apol_context_t * context, unsigned int range_match)
{
	if (f->context != NULL) {
		apol_context_destroy(&f->context);
	}
	f->context = context;
	f->flags = (f->flags & ~APOL_QUERY_FLAGS) | range_match;
	return 0;
}

char *apol_fs_use_render(const apol_policy_t * p, const qpol_fs_use_t * fsuse)
{
	char *context_str = NULL;
	char *line = NULL, *retval = NULL;
	const char *behavior_str = NULL;
	const char *fsname = NULL;
	const qpol_context_t *ctxt = NULL;
	uint32_t behavior;

	if (qpol_fs_use_get_behavior(p->p, fsuse, &behavior))
		goto cleanup;
	if ((behavior_str = apol_fs_use_behavior_to_str(behavior)) == NULL) {
		ERR(p, "%s", "Could not get behavior string.");
		goto cleanup;
	}

	if (qpol_fs_use_get_name(p->p, fsuse, &fsname))
		goto cleanup;

	if (behavior == QPOL_FS_USE_PSID) {
		context_str = strdup("");
	} else {
		if (qpol_fs_use_get_context(p->p, fsuse, &ctxt))
			goto cleanup;
		context_str = apol_qpol_context_render(p, ctxt);
		if (!context_str) {
			goto cleanup;
		}
	}
	if (asprintf(&line, "%s %s %s", behavior_str, fsname, context_str) < 0) {
		ERR(p, "%s", strerror(EINVAL));
		goto cleanup;
	}

	retval = line;
      cleanup:
	free(context_str);
	if (retval != line) {
		free(line);
	}
	return retval;
}
