/**
 *  @file
 *  Defines the public interface the policy modules.
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

#ifndef QPOL_MODULE_H
#define QPOL_MODULE_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stdint.h>

	typedef struct qpol_module qpol_module_t;

#define QPOL_MODULE_UNKNOWN 0
#define QPOL_MODULE_BASE    1
#define QPOL_MODULE_OTHER   2

/**
 *  Create a qpol module from a policy package file. Newly created
 *  modules are enabled by default.
 *  @param path The file from which to read the module. This string
 *  will be duplicated.
 *  @param module Pointer in which to store the newly allocated
 *  module. The caller is responsible for calling qpol_module_destroy()
 *  to free memory used by this module.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *module will be NULL.
 */
	extern int qpol_module_create_from_file(const char *path, qpol_module_t ** module);

/**
 *  Free all memory used by a qpol module and set it to NULL.  Does
 *  nothing if the pointer is already NULL.
 *  @param module Reference pointer to the module to destroy.
 */
	extern void qpol_module_destroy(qpol_module_t ** module);

/**
 *  Get the path of the policy package file used to create this module.
 *  @param module The module from which to get the path.
 *  @param path Pointer to the string in which to store the path. <b>The
 *  caller should not free this string.</b>
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *path will be NULL.
 */
	extern int qpol_module_get_path(const qpol_module_t * module, const char **path);

/**
 *  Get the name of a module.
 *  @param module The module from which to get the name.
 *  @param name Pointer to the string in which to store the name. <b>The
 *  caller should not free this string.</b> If the module is a base
 *  module the name will be NULL.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *name will be NULL.
 */
	extern int qpol_module_get_name(const qpol_module_t * module, const char **name);

/**
 *  Get the version of a module.
 *  @param module The module from which to get the version.
 *  @param version Pointer to string in which to store the version. <b>The
 *  caller should not free this string.</b>
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *version will be NULL.
 */
	extern int qpol_module_get_version(const qpol_module_t * module, const char **version);

/**
 *  Get the type of module (base or other).
 *  @param module The module from which to get the type.
 *  @param type Pointer to integer in which to store the type.  Value
 *  will be one of QPOL_MODULE_BASE or QPOL_MODULE_OTHER.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *type will be QPOL_MODULE_UNKNOWN.
 */
	extern int qpol_module_get_type(const qpol_module_t * module, int *type);

/**
 *  Determine if a module is enabled.
 *  @param module The module from which to get the enabled state.
 *  @param enabled Pointer to integer in which to store the state.
 *  Value will be 0 if module is disabled and non-zero if enabled.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *enabled will be 0.
 */
	extern int qpol_module_get_enabled(const qpol_module_t * module, int *enabled);

/**
 *  Enable or disable a module. Note that the caller must still
 *  invoke qpol_policy_rebuild() to update the policy.
 *  @param module The module to enable or disable.
 *  @param enabled Non-zero to enable the module, zero to disable.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and the module will remain unchanged.
 */
	extern int qpol_module_set_enabled(qpol_module_t * module, int enabled);
#ifdef	__cplusplus
}
#endif

#endif
