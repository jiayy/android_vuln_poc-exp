/**
 *  @file
 *  Public Interface for querying genfscons and fs_uses of a policy.
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

#ifndef APOL_FSCON_QUERY_H
#define APOL_FSCON_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include "context-query.h"
#include <string.h>
#include <qpol/policy.h>

	typedef struct apol_genfscon_query apol_genfscon_query_t;
	typedef struct apol_fs_use_query apol_fs_use_query_t;

/******************** genfscon queries ********************/

/**
 * Execute a query against all genfscons within the policy.  The
 * returned genfscons will be unordered.
 *
 * @param p Policy within which to look up genfscons.
 * @param g Structure containing parameters for query.	If this is
 * NULL then return all genfscons.
 * @param v Reference to a vector of qpol_genfscon_t. The vector will
 * be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_genfscon_get_by_query(const apol_policy_t * p, const apol_genfscon_query_t * g, apol_vector_t ** v);

/**
 * Allocate and return a new genfscon query structure.	All fields are
 * initialized, such that running this blank query results in
 * returning all genfscons within the policy. The caller must call
 * apol_genfscon_query_destroy() upon the return value afterwards.
 *
 * @return An initialized genfscon query structure, or NULL upon
 * error.
 */
	extern apol_genfscon_query_t *apol_genfscon_query_create(void);

/**
 * Deallocate all memory associated with the referenced genfscon
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param g Reference to a genfscon query structure to destroy.
 */
	extern void apol_genfscon_query_destroy(apol_genfscon_query_t ** g);

/**
 * Set a genfscon query to return only genfscons that act upon this
 * filesystem.
 *
 * @param p Policy handler, to report errors.
 * @param g Genfscon query to set.
 * @param fs Limit query to only genfscons with this filesystem, or
 * NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_genfscon_query_set_filesystem(const apol_policy_t * p, apol_genfscon_query_t * g, const char *fs);

/**
 * Set a genfscon query to return only genfscons that act upon this
 * relative path.  If the path includes a trailing slash, the search
 * will ingore that slash.
 *
 * @param p Policy handler, to report errors.
 * @param g Genfscon query to set.
 * @param path Limit query to only genfscons with this path, or NULL
 * to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_genfscon_query_set_path(const apol_policy_t * p, apol_genfscon_query_t * g, const char *path);

/**
 * Set a genfscon query to return only genfscons that act upon this
 * object class.
 *
 * @param p Policy handler, to report errors.
 * @param g Genfscon query to set.
 * @param class Limit query to only genfscons with this object class,
 * which must be one of QPOL_CLASS_BLK_FILE, QPOL_CLASS_CHR_FILE,
 * etc., or negative to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_genfscon_query_set_objclass(const apol_policy_t * p, apol_genfscon_query_t * g, int objclass);

/**
 * Set a genfscon query to return only genfscons matching a context.
 * This function takes ownership of the context, such that the caller
 * must not modify nor destroy it afterwards.
 *
 * @param p Policy handler, to report errors.
 * @param g Genfscon query to set.
 * @param context Limit query to only genfscons matching this context,
 * or NULL to unset this field.
 * @param range_match Specifies how to match the MLS range within the
 * context.  This must be one of APOL_QUERY_SUB, APOL_QUERY_SUPER, or
 * APOL_QUERY_EXACT.  This parameter is ignored if context is NULL.
 *
 * @return Always returns 0.
 */
	extern int apol_genfscon_query_set_context(const apol_policy_t * p,
						   apol_genfscon_query_t * g, apol_context_t * context, unsigned int range_match);

/**
 * Creates a string containing the textual representation of
 * a genfscon type.
 * @param p Reference to a policy.
 * @param genfscon Reference to the genfscon statement to be rendered.
 *
 * @return A newly allocated string on success, caller must free;
 * NULL on error.
 */
	extern char *apol_genfscon_render(const apol_policy_t * p, const qpol_genfscon_t * genfscon);

/******************** fs_use queries ********************/

/**
 * Execute a query against all fs_uses within the policy.  The
 * returned fs_use statements will be unordered.
 *
 * @param p Policy within which to look up fs_use statements.
 * @param f Structure containing parameters for query.	If this is
 * NULL then return all fs_use statements.
 * @param v Reference to a vector of qpol_fs_use_t.  The vector will
 * be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards. This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_fs_use_get_by_query(const apol_policy_t * p, const apol_fs_use_query_t * f, apol_vector_t ** v);

/**
 * Allocate and return a new fs_use query structure. All fields are
 * initialized, such that running this blank query results in
 * returning all fs_use statements within the policy.  The caller must
 * call apol_fs_use_query_destroy() upon the return value afterwards.
 *
 * @return An initialized fs_use query structure, or NULL upon error.
 */
	extern apol_fs_use_query_t *apol_fs_use_query_create(void);

/**
 * Deallocate all memory associated with the referenced fs_use query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param f Reference to a fs_use query structure to destroy.
 */
	extern void apol_fs_use_query_destroy(apol_fs_use_query_t ** f);

/**
 * Set a fs_use query to return only fs_use statements that act upon
 * this filesystem.
 *
 * @param p Policy handler, to report errors.
 * @param f fs_use query to set.
 * @param fs Limit query to only fs_use statements with this
 * filesystem, or NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_fs_use_query_set_filesystem(const apol_policy_t * p, apol_fs_use_query_t * f, const char *fs);

/**
 * Set a fs_use query to return only fs_use statements with this
 * behavior.
 *
 * @param p Policy handler, to report errors.
 * @param f fs_use query to set.
 * @param behavior Limit query to only fs_use statements with this
 * object class, which must be one of QPOL_FS_USE_XATTR,
 * QPOL_FS_USE_TRANS, etc., or negative to unset this field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_fs_use_query_set_behavior(const apol_policy_t * p, apol_fs_use_query_t * f, int behavior);

/**
 * Set a fs_use query to return only fs_use statements matching a
 * context.  This function takes ownership of the context, such that
 * the caller must not modify nor destroy it afterwards.  Note that if
 * a context is set, then the resulting query will never return
 * fs_use_psid statements.
 *
 * @param p Policy handler, to report errors.
 * @param f fs_use query to set.
 * @param context Limit query to only fs_use statements matching this
 * context, or NULL to unset this field.
 * @param range_match Specifies how to match the MLS range within the
 * context.  This must be one of APOL_QUERY_SUB, APOL_QUERY_SUPER, or
 * APOL_QUERY_EXACT.  This parameter is ignored if context is NULL.
 *
 * @return Always returns 0.
 */
	extern int apol_fs_use_query_set_context(const apol_policy_t * p,
						 apol_fs_use_query_t * f, apol_context_t * context, unsigned int range_match);

/**
 * Creates a string containing the textual representation of
 * a fs_use type.
 * @param p Reference to a policy.
 * @param fsuse Reference to the fs_use statement to be rendered.
 *
 * @return A newly allocated string on success, caller must free;
 * NULL on error.
 */
	extern char *apol_fs_use_render(const apol_policy_t * p, const qpol_fs_use_t * fsuse);

#ifdef	__cplusplus
}
#endif

#endif				       /* APOL_FSCON_QUERY_H */
