/**
 *  @file
 *  Defines the public interface the QPol policy.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Brandon Whalen bwhalen@tresys.com
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

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qpol/module.h>
#include <qpol/util.h>
#include "qpol_internal.h"

#include <sepol/policydb.h>
#include <sepol/policydb/module.h>

int qpol_module_create_from_file(const char *path, qpol_module_t ** module)
{
	sepol_module_package_t *smp = NULL;
	sepol_policy_file_t *spf = NULL;
	FILE *infile = NULL;
	int error = 0;
	char *tmp = NULL;
	char *data = NULL;
	ssize_t size;

	if (module)
		*module = NULL;

	if (!path || !module) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (!(*module = calloc(1, sizeof(qpol_module_t)))) {
		return STATUS_ERR;
	}

	if (!((*module)->path = strdup(path))) {
		error = errno;
		goto err;
	}

	if (sepol_policy_file_create(&spf)) {
		error = errno;
		goto err;
	}

	infile = fopen(path, "rb");
	if (!infile) {
		error = errno;
		goto err;
	}
	size = qpol_bunzip(infile, &data);

	if (size > 0) {
		if (!qpol_is_data_mod_pkg(data)) {
			error = ENOTSUP;
			goto err;
		}
		sepol_policy_file_set_mem(spf, data, size);
	} else {
		if (!qpol_is_file_mod_pkg(infile)) {
			error = ENOTSUP;
			goto err;
		}
		rewind(infile);
		sepol_policy_file_set_fp(spf, infile);
	}

	if (sepol_module_package_create(&smp)) {
		error = EIO;
		goto err;
	}

	if (sepol_module_package_info(spf, &((*module)->type), &((*module)->name), &tmp)) {
		error = EIO;
		goto err;
	}
	free(tmp);
	tmp = NULL;
	if (size > 0) {
		// Re setting the memory location has the effect of rewind
		// API is not accessible from here to explicitly "rewind" the
		// in-memory file.
		sepol_policy_file_set_mem(spf, data, size);
	} else {
		rewind(infile);
	}

	if (sepol_module_package_read(smp, spf, 0)) {
		error = EIO;
		goto err;
	}

	if (!((*module)->p = sepol_module_package_get_policy(smp))) {
		error = EIO;
		goto err;
	}
	/* set the module package's policy to NULL as the qpol module owns it now */
	smp->policy = NULL;

	(*module)->version = (*module)->p->p.version;
	(*module)->enabled = 1;

	sepol_module_package_free(smp);
	fclose(infile);
	if (data != NULL)
		free (data);
	sepol_policy_file_free(spf);

	return STATUS_SUCCESS;

      err:
	qpol_module_destroy(module);
	sepol_policy_file_free(spf);
	sepol_module_package_free(smp);
	if (infile)
		fclose(infile);
	if (data != NULL)
		free (data);
	if (tmp != NULL)
		free(tmp);
	errno = error;
	return STATUS_ERR;
}

void qpol_module_destroy(qpol_module_t ** module)
{
	if (!module || !(*module))
		return;

	free((*module)->path);
	free((*module)->name);
	sepol_policydb_free((*module)->p);
	free(*module);
	*module = NULL;
}

int qpol_module_get_path(const qpol_module_t * module, const char **path)
{
	if (!module || !path) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	*path = module->path;

	return STATUS_SUCCESS;
}

int qpol_module_get_name(const qpol_module_t * module, const char **name)
{
	if (!module || !name) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	*name = module->name;

	return STATUS_SUCCESS;
}

int qpol_module_get_version(const qpol_module_t * module, const char **version)
{
	if (!module || !version) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	*version = module->version;

	return STATUS_SUCCESS;
}

int qpol_module_get_type(const qpol_module_t * module, int *type)
{
	if (!module || !type) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	*type = module->type;

	return STATUS_SUCCESS;
}

int qpol_module_get_enabled(const qpol_module_t * module, int *enabled)
{
	if (!module || !enabled) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	*enabled = module->enabled;

	return STATUS_SUCCESS;
}

int qpol_module_set_enabled(qpol_module_t * module, int enabled)
{
	if (!module) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (enabled != module->enabled && module->parent) {
		module->parent->modified = 1;
	}
	module->enabled = enabled;

	return STATUS_SUCCESS;
}
