/**
 * @file
 *
 * Implementation of policy path object.
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

#include <config.h>

#include <apol/policy-path.h>
#include <apol/util.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "getline.h"

static const char *POLICY_PATH_MAGIC = "policy_list";
static const int POLICY_PATH_MAX_VERSION = 1;

struct apol_policy_path
{
	apol_policy_path_type_e path_type;
	char *base;
	apol_vector_t *modules;
};

apol_policy_path_t *apol_policy_path_create(apol_policy_path_type_e path_type, const char *path, const apol_vector_t * modules)
{
	apol_policy_path_t *p = NULL;

	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if ((p = calloc(1, sizeof(*p))) == NULL) {
		return NULL;
	}
	p->path_type = path_type;
	if ((p->base = strdup(path)) == NULL) {
		apol_policy_path_destroy(&p);
		return NULL;
	}
	if (p->path_type == APOL_POLICY_PATH_TYPE_MODULAR) {
		if (modules == NULL) {
			p->modules = apol_vector_create(free);
		} else {
			p->modules = apol_vector_create_from_vector(modules, apol_str_strdup, NULL, free);
		}
		if (p->modules == NULL) {
			apol_policy_path_destroy(&p);
			return NULL;
		}
		apol_vector_sort_uniquify(p->modules, apol_str_strcmp, NULL);
	}
	return p;
}

apol_policy_path_t *apol_policy_path_create_from_policy_path(const apol_policy_path_t * path)
{
	apol_policy_path_t *p;
	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	p = apol_policy_path_create(path->path_type, path->base, path->modules);
	return p;
}

apol_policy_path_t *apol_policy_path_create_from_file(const char *filename)
{
	FILE *f = NULL;
	apol_policy_path_t *path = NULL;
	apol_policy_path_type_e path_type;
	char *line = NULL, *s;
	apol_vector_t *header_tokens = NULL;
	size_t len;
	int read_base = 0, retval = -1, error = 0;

	if (filename == NULL) {
		error = EINVAL;
		goto cleanup;
	}
	if ((f = fopen(filename, "r")) == NULL) {
		error = errno;
		goto cleanup;
	}

	if (apol_getline(&line, &len, f) < 0) {
		error = EIO;
		goto cleanup;
	}
	apol_str_trim(line);
	if (strncmp(line, POLICY_PATH_MAGIC, strlen(POLICY_PATH_MAGIC)) != 0) {
		error = EIO;
		goto cleanup;
	}

	apol_str_trim(line);
	if ((header_tokens = apol_str_split(line, " ")) == NULL) {
		error = errno;
		goto cleanup;
	}
	if (apol_vector_get_size(header_tokens) < 3) {
		error = EIO;
		goto cleanup;
	}
	s = apol_vector_get_element(header_tokens, 1);
	if (atoi(s) == 0 || atoi(s) > POLICY_PATH_MAX_VERSION) {
		error = ENOTSUP;
		goto cleanup;
	}
	s = apol_vector_get_element(header_tokens, 2);
	if (strcmp(s, "monolithic") == 0) {
		path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
	} else if (strcmp(s, "modular") == 0) {
		path_type = APOL_POLICY_PATH_TYPE_MODULAR;
	} else {
		error = EIO;
		goto cleanup;
	}

	while (apol_getline(&line, &len, f) >= 0) {
		apol_str_trim(line);
		if (line[0] == '#') {
			continue;
		}
		if (!read_base) {
			/* trying to parse a base policy / monolithic policy line */
			if ((path = apol_policy_path_create(path_type, line, NULL)) == NULL) {
				error = errno;
				goto cleanup;
			}
			read_base = 1;
		} else {
			/* trying to parse a module line */
			if (path_type == APOL_POLICY_PATH_TYPE_MONOLITHIC) {
				error = EIO;
				goto cleanup;
			} else {
				if ((s = strdup(line)) == NULL || apol_vector_append(path->modules, s) < 0) {
					error = errno;
					free(s);
					goto cleanup;
				}
			}
		}
	}
	if (read_base == 0) {
		error = EIO;
		goto cleanup;
	}
	retval = 0;
      cleanup:
	if (f != NULL) {
		fclose(f);
	}
	free(line);
	apol_vector_destroy(&header_tokens);
	if (retval != 0) {
		apol_policy_path_destroy(&path);
		errno = error;
	}
	return path;
}

apol_policy_path_t *apol_policy_path_create_from_string(const char *path_string)
{
	apol_policy_path_t *p = NULL;
	apol_vector_t *tokens = NULL;
	apol_policy_path_type_e path_type;
	char *s;
	size_t i;
	if (path_string == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if ((tokens = apol_str_split(path_string, ":")) == NULL) {
		return NULL;
	}

	/* first token identifies the path type */
	if (apol_vector_get_size(tokens) < 2) {
		apol_vector_destroy(&tokens);
		return NULL;
	}
	s = apol_vector_get_element(tokens, 0);
	if (strcmp(s, "monolithic") == 0) {
		path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
	} else if (strcmp(s, "modular") == 0) {
		path_type = APOL_POLICY_PATH_TYPE_MODULAR;
	} else {
		apol_vector_destroy(&tokens);
		errno = EINVAL;
		return NULL;
	}

	/* second token identifies gives base path */
	s = apol_vector_get_element(tokens, 1);
	if ((p = apol_policy_path_create(path_type, s, NULL)) == NULL) {
		apol_vector_destroy(&tokens);
		return NULL;
	}

	if (path_type == APOL_POLICY_PATH_TYPE_MODULAR) {
		/* remainder are module paths */
		for (i = 2; i < apol_vector_get_size(tokens); i++) {
			s = apol_vector_get_element(tokens, i);
			if ((s = strdup(s)) == NULL || apol_vector_append(p->modules, s) < 0) {
				free(s);
				apol_vector_destroy(&tokens);
				apol_policy_path_destroy(&p);
				return NULL;
			}
		}
		apol_vector_sort_uniquify(p->modules, apol_str_strcmp, NULL);
	}
	return p;
}

void apol_policy_path_destroy(apol_policy_path_t ** path)
{
	if (path != NULL && *path != NULL) {
		free((*path)->base);
		apol_vector_destroy(&(*path)->modules);
		free(*path);
		*path = NULL;
	}
}

int apol_policy_path_compare(const apol_policy_path_t * a, const apol_policy_path_t * b)
{
	int cmp;
	if (a == NULL || b == NULL) {
		errno = EINVAL;
		return 0;
	}
	if ((cmp = a->path_type - b->path_type) != 0) {
		return cmp;
	}
	if ((cmp = strcmp(a->base, b->base)) != 0) {
		return cmp;
	}
	if (a->path_type == APOL_POLICY_PATH_TYPE_MODULAR) {
		/* only compare module vector if that field is relevant */
		size_t i;
		cmp = apol_vector_compare(a->modules, b->modules, apol_str_strcmp, NULL, &i);
		if (cmp != 0) {
			return cmp;
		}
	}
	return 0;
}

apol_policy_path_type_e apol_policy_path_get_type(const apol_policy_path_t * path)
{
	if (path == NULL) {
		errno = EINVAL;
		return APOL_POLICY_PATH_TYPE_MONOLITHIC;
	}
	return path->path_type;
}

const char *apol_policy_path_get_primary(const apol_policy_path_t * path)
{
	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return path->base;
}

const apol_vector_t *apol_policy_path_get_modules(const apol_policy_path_t * path)
{
	if (path == NULL || path->path_type != APOL_POLICY_PATH_TYPE_MODULAR) {
		errno = EINVAL;
		return NULL;
	}
	return path->modules;
}

int apol_policy_path_to_file(const apol_policy_path_t * path, const char *filename)
{
	FILE *f = NULL;
	char *path_type;
	size_t i;
	int retval = -1, error = 0;
	if (path == NULL || filename == NULL) {
		errno = EINVAL;
		goto cleanup;
	}
	if ((f = fopen(filename, "w")) == NULL) {
		error = errno;
		goto cleanup;
	}
	if (path->path_type == APOL_POLICY_PATH_TYPE_MODULAR) {
		path_type = "modular";
	} else {
		path_type = "monolithic";
	}
	if (fprintf(f, "%s %d %s\n", POLICY_PATH_MAGIC, POLICY_PATH_MAX_VERSION, path_type) < 0) {
		error = errno;
		goto cleanup;
	}
	if (fprintf(f, "%s\n", path->base) < 0) {
		error = errno;
		goto cleanup;
	}
	if (path->path_type == APOL_POLICY_PATH_TYPE_MODULAR) {
		for (i = 0; i < apol_vector_get_size(path->modules); i++) {
			char *m = apol_vector_get_element(path->modules, i);
			if (fprintf(f, "%s\n", m) < 0) {
				error = errno;
				goto cleanup;
			}
		}
	}

	retval = 0;
      cleanup:
	if (f != NULL) {
		fclose(f);
	}
	if (retval != 0) {
		errno = error;
	}
	return retval;
}

char *apol_policy_path_to_string(const apol_policy_path_t * path)
{
	char *path_type;
	char *s = NULL;
	size_t len = 0, i;
	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (path->path_type == APOL_POLICY_PATH_TYPE_MODULAR) {
		path_type = "modular";
	} else {
		path_type = "monolithic";
	}
	if (apol_str_appendf(&s, &len, "%s:%s", path_type, path->base) < 0) {
		return NULL;
	}
	if (path->path_type == APOL_POLICY_PATH_TYPE_MODULAR) {
		for (i = 0; i < apol_vector_get_size(path->modules); i++) {
			char *m = apol_vector_get_element(path->modules, i);
			if (apol_str_appendf(&s, &len, ":%s", m) < 0) {
				return NULL;
			}
		}
	}
	return s;
}

int apol_file_is_policy_path_list(const char *filename)
{
	FILE *f = NULL;
	char *line = NULL;
	size_t len = 0;
	int retval = -1, error = 0;

	if (filename == NULL) {
		error = EINVAL;
		goto cleanup;
	}
	if ((f = fopen(filename, "r")) == NULL) {
		error = errno;
		goto cleanup;
	}

	if (apol_getline(&line, &len, f) < 0) {
		error = EIO;
		goto cleanup;
	}
	apol_str_trim(line);
	if (strncmp(line, POLICY_PATH_MAGIC, strlen(POLICY_PATH_MAGIC)) != 0) {
		retval = 0;
		goto cleanup;
	}
	retval = 1;

      cleanup:
	if (f)
		fclose(f);
	free(line);
	if (retval < 0)
		errno = error;
	return retval;
}
