/**
 *  @file
 *  Public interface for representing and manipulating an
 *  apol_mls_level object.
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

#ifndef APOL_MLS_LEVEL_H
#define APOL_MLS_LEVEL_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include <qpol/policy.h>

	typedef struct apol_mls_level apol_mls_level_t;

/**
 * Allocate and return a new MLS level structure.  All fields are
 * initialized to nothing.  The caller must call
 * apol_mls_level_destroy() upon the return value afterwards.
 *
 * @return An initialized MLS level structure, or NULL upon error.
 */
	extern apol_mls_level_t *apol_mls_level_create(void);

/**
 * Allocate and return an MLS level structure, initialized by an
 * existing apol_mls_level_t object.  The caller must call
 * apol_mls_level_destroy() upon the return value afterwards.
 *
 * @param level Level to copy.  If NULL then the returned MLS level
 * will be initialized to nothing.
 *
 * @return An initialized MLS level structure, or NULL upon error.
 */
	extern apol_mls_level_t *apol_mls_level_create_from_mls_level(const apol_mls_level_t * level);

/**
 * Take a MLS level string (e.g., <b>S0:C0.C127</b>) and parse it.
 * Fill in a newly allocated apol_mls_level_t and return it.  This
 * function needs a policy to resolve dots within categories.  If the
 * string represents an illegal level then return NULL.	 The caller
 * must call apol_mls_level_destroy() upon the returned value
 * afterwards.
 *
 * @param p Policy within which to validate mls_level_string.
 * @param mls_level_string Pointer to a string representing a valid
 * MLS level.
 *
 * @return A filled in MLS level structure, or NULL upon error.
 */
	extern apol_mls_level_t *apol_mls_level_create_from_string(const apol_policy_t * p, const char *mls_level_string);

/**
 * Take a literal MLS level string (e.g., <b>S0:C0.C127</b>), fill in
 * a newly allocated apol_mls_level_t and return it.  The category
 * portion of the level will <strong>not</strong> be expanded (i.e.,
 * dots will not be resolved).  The caller must call
 * apol_mls_level_destroy() upon the returned value afterwards.
 *
 * Because this function creates a level without the benefit of a
 * policy, its category list is "incomplete" and thus most operations
 * will fail.  All functions other than apol_mls_level_render(),
 * apol_mls_level_convert(), and apol_mls_level_is_literal() will
 * result in error.  Call apol_mls_level_convert() to make a literal
 * MLS level complete, so that it can be used in all functions.
 *
 * @param mls_level_string Pointer to a string representing a
 * (possibly invalid) MLS level.
 *
 * @return A filled in MLS level structure, or NULL upon error.
 */
	extern apol_mls_level_t *apol_mls_level_create_from_literal(const char *mls_level_string);

/**
 * Create a new apol_mls_level_t and initialize it with a
 * qpol_mls_level_t.  The caller must call apol_mls_level_destroy()
 * upon the returned value afterwards.
 *
 * @param p Policy from which the qpol_mls_level_t was obtained.
 * @param qpol_level The libqpol level for which to create a new
 * apol level.	This level will not be altered by this call.
 *
 * @return A MLS level structure initialized to the value of
 * qpol_level, or NULL upon error.
 */
	extern apol_mls_level_t *apol_mls_level_create_from_qpol_mls_level(const apol_policy_t * p,
									   const qpol_mls_level_t * qpol_level);

/**
 * Create a new apol_mls_level_t and initialize it with a
 * qpol_level_t.	 The caller must call apol_mls_level_destroy()
 * upon the returned value afterwards.
 *
 * @param p Policy from which the qpol_level_t was obtained.
 * @param qpol_level The libqpol level for which to create a new
 * apol level.	This level will not be altered by this call.
 *
 * @return A MLS level structure initialized to the value of
 * qpol_level, or NULL upon error.
 */
	apol_mls_level_t *apol_mls_level_create_from_qpol_level_datum(const apol_policy_t * p, const qpol_level_t * qpol_level);

/**
 * Deallocate all memory associated with a MLS level structure and
 * then set it to NULL.	 This function does nothing if the level is
 * already NULL.
 *
 * @param level Reference to a MLS level structure to destroy.
 */
	extern void apol_mls_level_destroy(apol_mls_level_t ** level);

/**
 * Set the sensitivity component of an MLS level structure.  This
 * function duplicates the incoming string.
 *
 * @param p Error reporting handler, or NULL to use default handler.
 * @param level MLS level to modify.
 * @param sens New sensitivity component to set, or NULL to unset this
 * field.
 *
 * @return 0 on success, negative on error.
 */
	extern int apol_mls_level_set_sens(const apol_policy_t * p, apol_mls_level_t * level, const char *sens);

/**
 * Get the sensitivity component of an MLS level structure.
 *
 * @param level MLS level to query.
 *
 * @return The sensitivity, or NULL upon error if it has not yet been
 * set.  Do not modify the return value.
 */
	extern const char *apol_mls_level_get_sens(const apol_mls_level_t * level);

/**
 * Add a category component of an MLS level structure.	This function
 * duplicates the incoming string.
 *
 * @param p Error reporting handler, or NULL to use default handler.
 * @param level MLS level to modify.
 * @param cats New category component to append.
 *
 * @return 0 on success or < 0 on failure.
 */
	extern int apol_mls_level_append_cats(const apol_policy_t * p, apol_mls_level_t * level, const char *cats);

/**
 * Get the category component of an MLS level structure.  This will be
 * a vector of strings, sorted alphabetically.
 *
 * @param level MLS level to query.
 *
 * @return Vector of categories, or NULL upon error.  Be aware that
 * the vector could be empty if no categories have been set.  Do not
 * modify the return value.
 */
	extern const apol_vector_t *apol_mls_level_get_cats(const apol_mls_level_t * level);

/**
 * Compare two levels and determine their relationship to each other.
 * Both levels must have their respective sensitivity and categories
 * set.	 Levels may contain aliases in place of primary names.	If
 * level2 is NULL then this always returns APOL_MLS_EQ.
 *
 * @param p Policy within which to look up MLS information.
 * @param target Target MLS level to compare.
 * @param search Source MLS level to compare.
 *
 * @return One of APOL_MLS_EQ, APOL_MLS_DOM, APOL_MLS_DOMBY, or
 * APOL_MLS_INCOMP; < 0 on error.
 *
 * @see apol_mls_level_validate()
 */
	extern int apol_mls_level_compare(const apol_policy_t * p, const apol_mls_level_t * level1,
					  const apol_mls_level_t * level2);

/**
 * Given a level, determine if it is legal according to the supplied
 * policy.  This function will convert from aliases to canonical forms
 * as necessary.
 *
 * @param h Error reporting handler.
 * @param p Policy within which to look up MLS information.
 * @param level Level to check.
 *
 * @return 1 If level is legal, 0 if not; < 0 on error.
 *
 * @see apol_mls_level_compare()
 */
	extern int apol_mls_level_validate(const apol_policy_t * p, const apol_mls_level_t * level);

/**
 * Creates a string containing the textual representation of
 * a MLS level.
 * @param p Policy from which the MLS level is a member.  If NULL,
 * then attempt to treat the level as an incomplete level (as per
 * apol_mls_level_create_from_literal()).
 * @param level MLS level to render.
 *
 * @return A newly allocated string, or NULL upon error.  The caller
 * is responsible for calling free() upon the return value.
 */
	extern char *apol_mls_level_render(const apol_policy_t * p, const apol_mls_level_t * level);

/**
 * Given a policy and a MLS level created by
 * apol_mls_level_create_from_literal(), convert the level to have a
 * valid ("complete") list of categories.  This will take the literal
 * string stored within the level and resolve its category lists, such
 * as by expanding dots.  The level will keep its literal string, so
 * that it may be converted again if given a different policy.
 *
 * @param p Policy containing category information.
 * @param level MLS level to convert.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int apol_mls_level_convert(const apol_policy_t * p, apol_mls_level_t * level);

/**
 * Determine if a level is literal (i.e., created from
 * apol_mls_level_create_from_literal()).  Note that converting a
 * literal level (apol_mls_level_convert()) completes the level, but
 * it is still a literal level.
 *
 * @param level Level to query.
 *
 * @return > 0 value if the level is literal, 0 if not, < 0 if unknown
 * or upon error.
 */
	extern int apol_mls_level_is_literal(const apol_mls_level_t * level);

#ifdef	__cplusplus
}
#endif

#endif				       /* APOL_MLS_LEVEL_H */
