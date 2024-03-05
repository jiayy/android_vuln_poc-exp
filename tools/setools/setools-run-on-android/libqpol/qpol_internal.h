/**
 *  @file
 *  Defines common debug symbols and the internal policy structure.
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

#ifndef QPOL_INTERNAL_H
#define QPOL_INTERNAL_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <sepol/handle.h>
#include <qpol/policy.h>
#include <stdio.h>

#define STATUS_SUCCESS  0
#define STATUS_ERR     -1
#define STATUS_NODATA   1

#define QPOL_MSG_ERR  1
#define QPOL_MSG_WARN 2
#define QPOL_MSG_INFO 3

	struct qpol_extended_image;
	struct qpol_policy;

	struct qpol_module
	{
		char *name;
		char *path;
		char *version;
		int type;
		struct sepol_policydb *p;
		int enabled;
		struct qpol_policy *parent;
	};

	struct qpol_policy
	{
		struct sepol_policydb *p;
		struct sepol_handle *sh;
		qpol_callback_fn_t fn;
		void *varg;
		int options;
		int type;
		int modified;
		struct qpol_extended_image *ext;
		struct qpol_module **modules;
		size_t num_modules;
		char *file_data;
		size_t file_data_sz;
		int file_data_type;
	};
/* qpol_policy_t.file_data_type will be one of the following to denote
 * the proper method of destroying the data:
 * _BIN if policy is from a binary source (modular or kernel) destroy is a no-op
 * _MMAP if policy is from a file and destroy should call munmap
 * _MEM if policy is from open_from_memory and destroy should call free */
#define QPOL_POLICY_FILE_DATA_TYPE_BIN  0
#define QPOL_POLICY_FILE_DATA_TYPE_MMAP 1
#define QPOL_POLICY_FILE_DATA_TYPE_MEM  2

/**
 *  Create an extended image for a policy. This function modifies the policydb
 *  by adding additional records and information about attributes, initial sids
 *  and other components not normally written to a binary policy file. Subsequent
 *  calls to this function have no effect.
 *  @param policy The policy for which the extended image should be created.
 *  @return Returns 0 on success and < 0 on failure. If the call fails,
 *  errno will be set; the state of the policy is not guaranteed to be stable
 *  if this call fails.
 */
	int policy_extend(qpol_policy_t * policy);

	extern void qpol_handle_msg(const qpol_policy_t * policy, int level, const char *fmt, ...);
	int qpol_is_file_binpol(FILE * fp);
	int qpol_is_file_mod_pkg(FILE * fp);
/**
 * Returns the version number of the binary policy.  Note that this
 * will rewind the file pointer.
 *
 * @return Non-negative policy version, or -1 general error for, -2
 * wrong magic number for file, or -3 problem reading file.
 */
	int qpol_binpol_version(FILE * fp);

/**
 * Returns true if the file is a module package.
 * @return Returns 1 for module packages, 0 otherwise.
 */
	int qpol_is_data_mod_pkg(char * data);

#define ERR(policy, format, ...) qpol_handle_msg(policy, QPOL_MSG_ERR, format, __VA_ARGS__)
#define WARN(policy, format, ...) qpol_handle_msg(policy, QPOL_MSG_WARN, format, __VA_ARGS__)
#define INFO(policy, format, ...) qpol_handle_msg(policy, QPOL_MSG_INFO, format, __VA_ARGS__)

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_INTERNAL_H */
