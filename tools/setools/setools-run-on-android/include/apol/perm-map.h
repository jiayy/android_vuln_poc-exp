/**
 * @file
 *
 * Permission mapping routines for libapol.  These maps assoicate all
 * object class permissions with read, write, read&write, and none
 * access.  These maps are used, for example, by an information flow
 * analysis.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
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

#ifndef APOL_PERMMAP_H
#define APOL_PERMMAP_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"

#define APOL_PERMMAP_MAX_WEIGHT 10
#define APOL_PERMMAP_MIN_WEIGHT 1

#define APOL_PERMMAP_UNMAPPED	0x00   /* defined object/perm, but no map */
#define	APOL_PERMMAP_READ	0x01
#define APOL_PERMMAP_WRITE	0x02
#define APOL_PERMMAP_BOTH	(APOL_PERMMAP_READ | APOL_PERMMAP_WRITE)
#define APOL_PERMMAP_NONE	0x10

/**
 * Read a permission map from a file into a policy.  If there is a
 * non-fatal error while loading (e.g., file declared an object class
 * that does not exist within the policy) then generate a warning
 * string and send it to the error handler stored within the policy.
 *
 * If a permission map was already loaded, then the existing one will
 * be destroyed.
 *
 * @param p Policy to which store permission map.
 * @param filename Name of file containing permission map.
 *
 * @return 0 on success, > 0 on success with warnings, < 0 on error.
 */
	extern int apol_policy_open_permmap(apol_policy_t * p, const char *filename);

/**
 * @deprecated Use apol_policy_open_permmap().
 */
	extern int apol_permmap_load(apol_policy_t * p, const char *filename) __attribute__ ((deprecated));

/**
 * Write the contents of permission map to a file.  Any existing file
 * will be overwritten.
 *
 * @param p Policy containing permission map.
 * @param filename Destination filename.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int apol_policy_save_permmap(const apol_policy_t * p, const char *filename);

/**
 * @deprecated Use apol_policy_save_permmap().
 */
	extern int apol_permmap_save(apol_policy_t * p, const char *filename) __attribute__ ((deprecated));

/**
 * Given a class and permission name, look up that permission mapping
 * within a policy's permission map.  Set the reference variables map
 * and weight to the mapping.
 *
 * @param p Policy containing permission map.
 * @param class_name Name of class to find.
 * @param perm_name Permission within class to find.
 * @param map Location to store mapping, one of APOL_PERMMAP_UNMAPPED,
 * etc.
 * @param weight Weight of this permission, a value between
 * APOL_PERMMAP_MIN_WEIGHT and APOL_PERMMAP_MAX_WEIGHT, inclusive.
 *
 * @return 0 if class and permission were found, < 0 on error or if
 * not found.
 */
	extern int apol_policy_get_permmap(const apol_policy_t * p, const char *class_name, const char *perm_name, int *map,
					   int *weight);

/**
 * @deprecated Use apol_policy_get_permmap().
 */
	extern int apol_permmap_get(apol_policy_t * p, const char *class_name, const char *perm_name, int *map, int *weight)
		__attribute__ ((deprecated));

/**
 * Given a class and permission name, set that permission's map and
 * weight within the policy's permission map.
 *
 * @param p Policy containing permission map.
 * @param class_name Name of class to find.
 * @param perm_name Permission within class to find.
 * @param map New map value, one of APOL_PERMMAP_UNMAPPED, etc.
 * @param weight New weight of this permission.  If the value will be
 * clamped to be between APOL_PERMMAP_MIN_WEIGHT and
 * APOL_PERMMAP_MAX_WEIGHT, inclusive.
 *
 * @return 0 if permission map was changed, < 0 on error or if not
 * found.
 */
	extern int apol_policy_set_permmap(apol_policy_t * p, const char *class_name, const char *perm_name, int map, int weight);

/**
 * @deprecated Use apol_policy_set_permmap().
 */
	extern int apol_permmap_set(apol_policy_t * p, const char *class_name, const char *perm_name, int map, int weight)
		__attribute__ ((deprecated));

#ifdef	__cplusplus
}
#endif

#endif				       /*APOL_PERMMAP_H */
