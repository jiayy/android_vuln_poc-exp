/**
 * @file
 *
 * Miscellaneous, uncategorized functions for libqpol.
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

#ifndef QPOL_UTIL_H
#define QPOL_UTIL_H

#ifdef	__cplusplus
extern "C"
{
#endif

/**
 * Return an immutable string describing this library's version.
 *
 * @return String describing this library.
 */
	extern const char *libqpol_get_version(void);

/**
 * Find the "default" policy file on the currently running system.
 * First try looking for a monolithic source policy; if that does not
 * exist then try a monolithic binary policy.
 *
 * @param path Buffer to store the policy's path.  The caller is
 * responsible for free()ing this string.
 *
 * @return 0 if a policy was found, > 0 if not, < 0 upon error.
 */
	extern int qpol_default_policy_find(char **path);

/* bunzip() a file to '*data', returning the total number of uncompressed bytes
 * in the file.  Returns -1 if file could not be decompressed. */
	extern ssize_t qpol_bunzip(FILE *f, char **data);

#ifdef	__cplusplus
}
#endif

#endif
