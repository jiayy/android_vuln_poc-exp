/**
 *  @file
 *  Public interface for representing and manipulating the
 *  apol_mls_range object.
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

#ifndef APOL_MLS_RANGE_H
#define APOL_MLS_RANGE_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "mls_level.h"
#include "policy.h"
#include "vector.h"
#include <qpol/policy.h>

	typedef struct apol_mls_range apol_mls_range_t;

/**
 * Allocate and return a new MLS range structure.  All fields are
 * initialized to nothing.  The caller must call
 * apol_mls_range_destroy() upon the return value afterwards.
 *
 * @return An initialized MLS range structure, or NULL upon error.
 */
	extern apol_mls_range_t *apol_mls_range_create(void);

/**
 * Allocate and return a new MLS range structure, initialized by an
 * existing apol_mls_range_t.  The caller must call
 * apol_mls_range_destroy() upon the return value afterwards.
 *
 * @param range Range to copy.  If NULL then the returned MLS range
 * will be initialized to nothing.
 *
 * @return An initialized MLS range structure, or NULL upon error.
 */
	extern apol_mls_range_t *apol_mls_range_create_from_mls_range(const apol_mls_range_t * range);

/**
 * Take a MLS range string (e.g., <b>S0:C0.C10-S1:C0.C127</b>) and
 * parse it.  Fill in a newly allocated apol_mls_range_t and return
 * it.  This function needs a policy to resolve dots within categories
 * and to ensure that the high level dominates the low.  If the string
 * represents an illegal range then return NULL.  The caller must call
 * apol_mls_range_destroy() upon the returned value afterwards.
 *
 * @param p Policy within which to validate mls_range_string.
 * @param mls_range_string Pointer to a string representing a valid
 * MLS range.
 *
 * @return A filled in MLS range structure, or NULL upon error.
 */
	extern apol_mls_range_t *apol_mls_range_create_from_string(const apol_policy_t * p, const char *mls_range_string);

/**
 * Take a literal MLS range string (e.g.,
 * <b>S0:C0.C10-S1:C0.C127</b>), fill in a newly allocated
 * apol_mls_range_t and return it.  The category portions of the
 * levels will <strong>not</strong> be expanded (i.e., dots will not
 * be resolved); likewise there is no check that the high level
 * dominates the low.  The caller must call apol_mls_range_destroy()
 * upon the returned value afterwards.
 *
 * Because this function creates a range without the benefit of a
 * policy, its levels are "incomplete" and thus most operations will
 * fail.  Call apol_mls_range_convert() to make a literal MLS range
 * complete, so that it can be used in all functions.
 *
 * @param mls_range_string Pointer to a string representing a
 * (possibly invalid) MLS range.
 *
 * @return A filled in MLS range structure, or NULL upon error.
 */
	extern apol_mls_range_t *apol_mls_range_create_from_literal(const char *mls_range_string);

/**
 * Create a new apol_mls_range_t and initialize it with a
 * qpol_mls_range_t.  The caller must call apol_mls_range_destroy()
 * upon the return value afterwards.
 *
 * @param p Policy from which the qpol_mls_range_t was obtained.
 * @param qpol_range The libqpol range for which to create a new
 * apol range.	This range will not be altered by this call.
 *
 * @return A MLS range structure initialized to the value of
 * qpol_range, or NULL upon error.
 */
	extern apol_mls_range_t *apol_mls_range_create_from_qpol_mls_range(const apol_policy_t * p,
									   const qpol_mls_range_t * qpol_range);

/**
 * Deallocate all memory associated with a MLS range structure and
 * then set it to NULL.	 This function does nothing if the range is
 * already NULL.
 *
 * @param range Reference to a MLS range structure to destroy.
 */
	extern void apol_mls_range_destroy(apol_mls_range_t ** range);

/**
 * Set the low level component of a MLS range structure.  This
 * function takes ownership of the level, such that the caller must
 * not modify nor destroy it afterwards.  It is legal to pass in the
 * same pointer for the range's low and high level.
 *
 * @param p Error reporting handler, or NULL to use default handler.
 * @param range MLS range to modify.
 * @param level New low level for range, or NULL to unset this field.
 *
 * @return 0 on success or < 0 on failure.
 */
	extern int apol_mls_range_set_low(const apol_policy_t * p, apol_mls_range_t * range, apol_mls_level_t * level);

/**
 * Set the high level component of a MLS range structure.  This
 * function takes ownership of the level, such that the caller must
 * not modify nor destroy it afterwards.  It is legal to pass in the
 * same pointer for the range's low and high level.
 *
 * @param p Error reporting handler, or NULL to use default handler.
 * @param range MLS range to modify.
 * @param level New high level for range, or NULL to unset this field.
 *
 * @return 0 on success or < 0 on failure.
 */
	extern int apol_mls_range_set_high(const apol_policy_t * p, apol_mls_range_t * range, apol_mls_level_t * level);

/**
 * Get the low level component of a MLS range structure.
 *
 * @param range MLS range to query.
 *
 * @return Low level, or NULL upon error or if not yet set.  Do not
 * modify the return value.
 */
	extern const apol_mls_level_t *apol_mls_range_get_low(const apol_mls_range_t * range);

/**
 * Get the high level component of a MLS range structure.
 *
 * @param range MLS range to query.
 *
 * @return High level, or NULL upon error or if not yet set.  Do not
 * modify the return value.
 */
	extern const apol_mls_level_t *apol_mls_range_get_high(const apol_mls_range_t * range);

/**
 * Compare two ranges, determining if one matches the other.  The
 * fifth parameter gives how to match the ranges.  For APOL_QUERY_SUB,
 * if search is a subset of target.  For APOL_QUERY_SUPER, if search
 * is a superset of target.  Other valid compare types are
 * APOL_QUERY_EXACT and APOL_QUERY_INTERSECT.  If a range is not valid
 * according to the policy then this function returns -1.  If search
 * is NULL then comparison always succeeds.
 *
 * @param p Policy within which to look up MLS information.
 * @param target Target MLS range to compare.
 * @param search Source MLS range to compare.
 * @param range_compare_type Specifies how to compare the ranges.
 *
 * @return 1 If comparison succeeds, 0 if not; -1 on error.
 */
	extern int apol_mls_range_compare(const apol_policy_t * p,
					  const apol_mls_range_t * target, const apol_mls_range_t * search,
					  unsigned int range_compare_type);

/**
 * Determine if a range completely contains a subrange given a certain
 * policy.  If a range is not valid according to the policy then this
 * function returns -1.
 *
 * @param p Policy within which to look up MLS information.
 * @param range Parent range to compare.
 * @param subrange Child range to which compare.
 *
 * @return 1 If comparison succeeds, 0 if not; -1 on error.
 */
	extern int apol_mls_range_contain_subrange(const apol_policy_t * p, const apol_mls_range_t * range,
						   const apol_mls_range_t * subrange);
/**
 * Given a range, determine if it is legal according to the supplied
 * policy.  This function will convert from aliases to canonical forms
 * as necessary.
 *
 * @param p Policy within which to look up MLS information.
 * @param range Range to check.
 *
 * @return 1 If range is legal, 0 if not; -1 on error.
 */
	extern int apol_mls_range_validate(const apol_policy_t * p, const apol_mls_range_t * range);

/**
 * Given a range, return a vector of levels (type apol_mls_level_t *)
 * that constitutes that range.  The vector will be sorted in policy order.
 *
 * @param p Policy from which the level and category definitions reside.
 * @param range Range to expand.
 *
 * @return Vector of levels, or NULL upon error.  The caller is
 * responsible for calling apol_vector_destroy() upon the returned
 * value, passing apol_mls_level_free() as the second parameter.
 */
	extern apol_vector_t *apol_mls_range_get_levels(const apol_policy_t * p, const apol_mls_range_t * range);

/**
 * Creates a string containing the textual representation of
 * a MLS range.
 *
 * @param p Policy from which the MLS range is a member.  If NULL,
 * then attempt to treat the range's levels as incomplete levels (as
 * per apol_mls_level_create_from_literal()).
 * @param range MLS range to render.
 *
 * @return A newly allocated string, or NULL upon error.  The caller
 * is responsible for calling free() upon the return value.
 */
	extern char *apol_mls_range_render(const apol_policy_t * p, const apol_mls_range_t * range);

/**
 * Given a range, convert any literal MLS levels within it (as per
 * apol_mls_level_convert()) to a complete level.  If the range has no
 * levels or has no literal levels then do nothing.
 *
 * @param p Policy containing category information.
 * @param range Range to convert.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int apol_mls_range_convert(const apol_policy_t * p, apol_mls_range_t * range);

/**
 * Determine if the range contains any literal levels.  (Levels that
 * have been converted are still considered literal.)
 *
 * @param range Range to query.
 *
 * @return > 0 value if the range has a literal level, 0 if not, < 0
 * if unknown or upon error.
 */
	extern int apol_mls_range_is_literal(const apol_mls_range_t * range);

#ifdef	__cplusplus
}
#endif

#endif				       /* APOL_MLS_RANGE_H */
