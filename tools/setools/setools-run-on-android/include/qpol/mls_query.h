/**
 *  @file
 *  Defines the public interface for searching and iterating over
 *  policy MLS components.
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

#ifndef QPOL_MLS_QUERY_H
#define QPOL_MLS_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

	typedef struct qpol_level qpol_level_t;
	typedef struct qpol_cat qpol_cat_t;
	typedef struct qpol_mls_range qpol_mls_range_t;
	typedef struct qpol_mls_level qpol_mls_level_t;

#include <qpol/iterator.h>
#include <qpol/policy.h>

/* level */
/**
 *  Get datum for a security level by (sensitivity) name.
 *  @param policy The policy from which to get the level datum.
 *  @param name The sensitivity name; searching is case sensitive.
 *  @param datum Pointer in which to store the level datum. Must be non-NULL.
 *  The caller should not free this pointer.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *datum will be NULL.
 */
	extern int qpol_policy_get_level_by_name(const qpol_policy_t * policy, const char *name, const qpol_level_t ** datum);

/**
 *  Get an iterator for the levels in a policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator of type qpol_level_t* returned;
 *  The caller is responsible for calling qpol_iterator_destroy
 *  to free memory used; it is important to note that the iterator
 *  is valid only as long as the policy is unchanged.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_level_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter);

/**
 *  Determine if a level is an alias for another level.
 *  @param policy The policy associated with the level datum.
 *  @param datum The level to check.
 *  @param isalias Pointer in which to store the alias state of
 *  the level. Must be non-NULL.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *isalias will be 0 (false).
 */
	extern int qpol_level_get_isalias(const qpol_policy_t * policy, const qpol_level_t * datum, unsigned char *isalias);

/**
 *  Get the integer value associated with the sensitivity of a level.
 *  Values range from 1 to the number of declared levels in the policy.
 *  @param policy The policy associated with the level.
 *  @param datum The level datum from which to get the value.
 *  @param value Pointer to the integer to set to value. Must be non-NULL.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *value will be 0.
 */
	extern int qpol_level_get_value(const qpol_policy_t * policy, const qpol_level_t * datum, uint32_t * value);

/**
 *  Get an iterator for the categories associated with a level.
 *  @param policy The policy associated with the level.
 *  @param datum The level from which to get the categories.
 *  @param cats Iterator of type qpol_cat_t* returned;
 *  the categories are in policy order. The caller is responsible
 *  for calling qpol_iterator_destroy to free memory used;
 *  it is important to note that the iterator is valid only as long
 *  as the policy is unchanged.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *cats will be NULL.
 */
	extern int qpol_level_get_cat_iter(const qpol_policy_t * policy, const qpol_level_t * datum, qpol_iterator_t ** cats);

/**
 *  Get the name which identifies a level from its datum.
 *  @param policy The policy associated with the level.
 *  @param datum The level from which to get the name.
 *  @param name Pointer in which to store the name. Must be non-NULL;
 *  the caller should not free this string. If the sensitivity is an
 *  alias, the primary name will be returned.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *name will be NULL.
 */
	extern int qpol_level_get_name(const qpol_policy_t * policy, const qpol_level_t * datum, const char **name);

/**
 *  Get an iterator for the list of aliases for a level.
 *  @param policy The policy associated with the level.
 *  @param datum The level for which to get aliases.
 *  @param aliases Iterator of type char* returned; the caller is
 *  responsible for calling qpol_iterator_destroy to free
 *  memory used; it is important to note that the iterator is valid
 *  only as long as the policy is unchanged. If a level has no aliases,
 *  the iterator will be at end and have size 0.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *aliases will be NULL.
 */
	extern int qpol_level_get_alias_iter(const qpol_policy_t * policy, const qpol_level_t * datum, qpol_iterator_t ** aliases);

/* cat */
/**
 *  Get the datum for a category by name.
 *  @param policy The policy from which to get the category.
 *  @param name The name of the category; searching is case sensitive.
 *  @param datum Pointer in which to store the datum; the caller should
 *  not free this pointer.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *datum will be NULL.
 */
	extern int qpol_policy_get_cat_by_name(const qpol_policy_t * policy, const char *name, const qpol_cat_t ** datum);

/**
 *  Get an iterator for the categories declared in a policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator of type qpol_cat_t* returned;
 *  the categories are in policy order. The caller is responsible
 *  for calling qpol_iterator_destroy to free the memory used;
 *  it is important to note that the iterator is only valid as
 *  long as the policy is unchanged.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_cat_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter);

/**
 *  Get the integer value associated with a category. Values range
 *  from 1 to the number of categories declared in the policy.
 *  @param policy The policy associated with the category.
 *  @param datum The category for which to get the value.
 *  @param value Pointer to the integer to set to value. Must be non-NULL.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *value will be 0.
 */
	extern int qpol_cat_get_value(const qpol_policy_t * policy, const qpol_cat_t * datum, uint32_t * value);

/**
 *  Determine if a category is an alias for another category.
 *  @param policy The policy associated with the category.
 *  @param datum The category to check.
 *  @param isalias Pointer in which to store the alias state of the
 *  category; must be non-NULL.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *isalias will be 0 (false).
 */
	extern int qpol_cat_get_isalias(const qpol_policy_t * policy, const qpol_cat_t * datum, unsigned char *isalias);

/**
 *  Get the name which identifies a category from its datum.
 *  @param policy The policy associated with the category.
 *  @param datum The category from which to get the name.
 *  @param name Pointer in which to store the name. Must be non-NULL;
 *  the caller should not free the string. If the category is an alias
 *  the primary name will be returned.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *name will be NULL.
 */
	extern int qpol_cat_get_name(const qpol_policy_t * policy, const qpol_cat_t * datum, const char **name);

/**
 *  Get an iterator for the list of aliases for a category.
 *  @param policy The policy associated with the category.
 *  @param datum The category for which to get aliases.
 *  @param aliases Iterator of type char* returned; the caller is
 *  responsible for calling qpol_iterator_destroy to free
 *  memory used; it is important to note that the iterator is valid
 *  only as long as the policy is unchanged. If a category has no aliases,
 *  the iterator will be at end and have size 0.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *aliases will be NULL.
 */
	extern int qpol_cat_get_alias_iter(const qpol_policy_t * policy, const qpol_cat_t * datum, qpol_iterator_t ** aliases);

/* mls range */
/**
 *  Get the low level from a MLS range.
 *  @param policy The policy associated with the MLS components of range.
 *  @param range The range from which to get the low level.
 *  @param level Pointer in which to store the level; the caller
 *  should not free this pointer.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *level will be NULL.
 */
	extern int qpol_mls_range_get_low_level(const qpol_policy_t * policy, const qpol_mls_range_t * range,
						const qpol_mls_level_t ** level);

/**
 *  Get the high level from a MLS range.
 *  @param policy The policy associated with the MLS components of range.
 *  @param range The range from which to get the high level.
 *  @param level Pointer in which to store the level; the caller
 *  should not free this pointer.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *level will be NULL.
 */
	extern int qpol_mls_range_get_high_level(const qpol_policy_t * policy, const qpol_mls_range_t * range,
						 const qpol_mls_level_t ** level);

/* mls_level */
/**
 *  Get the name of the sensitivity from a MLS level.
 *  @param policy The policy associated with the MLS components of level.
 *  @param level The level from which to get the sensitivity name.
 *  @param name Pointer in which to store the name; the caller
 *  should not free this string.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *name will be NULL.
 */
	extern int qpol_mls_level_get_sens_name(const qpol_policy_t * policy, const qpol_mls_level_t * level, const char **name);

/**
 *  Get an iterator for the categories in a MLS level. The list will be
 *  in policy order.
 *  @param policy The policy associated with the MLS components of level.
 *  @param level The level from which to get the categories.
 *  @param cats Iterator of type qpol_cat_t* returned; the list is in
 *  policy order.  The caller is responsible for calling
 *  qpol_iterator_destroy to free memory used; it is important to note
 *  that an iterator is only valid as long as the policy is unchanged.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *cats will be NULL.
 */
	extern int qpol_mls_level_get_cat_iter(const qpol_policy_t * policy, const qpol_mls_level_t * level,
					       qpol_iterator_t ** cats);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_MLS_QUERY_H */
