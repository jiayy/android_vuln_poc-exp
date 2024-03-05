 /**
 *  @file
 *  Defines the public interface for searching and iterating over types.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006-2008 Tresys Technology, LLC
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

#ifndef QPOL_TYPE_QUERY_H
#define QPOL_TYPE_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>

	typedef struct qpol_type qpol_type_t;

/**
 *  Get the datum for a type by name.
 *  @param policy The policy from which to get the type.
 *  @param name The name of the type; searching is case sensitive.
 *  @param datum Pointer in which to store the type datum; the caller
 *  should not free this pointer.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *datum will be NULL.
 */
	extern int qpol_policy_get_type_by_name(const qpol_policy_t * policy, const char *name, const qpol_type_t ** datum);

/**
 *  Get an iterator for types (including attributes and aliases)
 *  declared in the policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator of type qpol_type_t* returned;
 *  the caller is responsible for calling qpol_iterator_destroy to
 *  free memory used; it is important to note that the iterator is
 *  valid only as long as the policy is unchanged.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_type_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter);

/**
 *  Get the integer value associated with a type. Values range from 1
 *  to the number of types declared in the policy.
 *  @param policy The policy associated with the type.
 *  @param datum The type from which to get the value.
 *  @param value Pointer to the integer in which to store value.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and value will be 0.
 */
	extern int qpol_type_get_value(const qpol_policy_t * policy, const qpol_type_t * datum, uint32_t * value);

/**
 *  Determine whether a given type is an alias for another type.
 *  @param policy The policy associated with the type.
 *  @param datum The type to check.
 *  @param isalias Pointer to be set to 1 (true) if the type is an alias
 *  and 0 (false) otherwise.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *isalias will be 0 (false).
 */
	extern int qpol_type_get_isalias(const qpol_policy_t * policy, const qpol_type_t * datum, unsigned char *isalias);

/**
 *  Determine whether a given type is an attribute.
 *  @param policy The policy associated with the type.
 *  @param datum The type to check.
 *  @param isattr Pointer to be set to 1 (true) if the type is an
 *  attribute and 0 (false) otherwise.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *isattr will be 0 (false).
 */
	extern int qpol_type_get_isattr(const qpol_policy_t * policy, const qpol_type_t * datum, unsigned char *isattr);

/**
 *  Determine whether a given type has been marked as enforcing
 *  (default) or as permissive.  If the policy does not support
 *  permissive types, then all types are enforcing.  Attributes are
 *  always enforcing.
 *
 *  @param policy The policy associated with the type.
 *  @param datum The type to check.
 *  @param ispermissive Pointer to be set to 1 (true) if the type is
 *  permissive and 0 (false) otherwise.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *ispermissive will be 0 (false).
 */
	extern int qpol_type_get_ispermissive(const qpol_policy_t * policy, const qpol_type_t * datum, unsigned char *ispermissive);

/**
 *  Get an iterator for the list of types in an attribute.
 *  @param policy The policy associated with the attribute.
 *  @param datum The attribute from which to get the types.
 *  @param types Iterator of type qpol_type_t* returned;
 *  the caller is responsible for calling qpol_iterator_destroy to
 *  free memory used; it is important to note that the iterator is
 *  valid only as long as the policy is unchanged.
 *  @return Returns 0 on success, > 0 if the type is not an attribute
 *  and < 0 on failure; if the call fails, errno will be set and
 *  *types will be NULL. If the type is not an attribute *types will
 *  be NULL.
 */
	extern int qpol_type_get_type_iter(const qpol_policy_t * policy, const qpol_type_t * datum, qpol_iterator_t ** types);

/**
 *  Get an iterator for the list of attributes given to a type.
 *  @param policy The policy associated with the type.
 *  @param datum The type for which to get the attributes.
 *  @param attrs Iterator of type qpol_type_t* returned;
 *  the caller is responsible for calling qpol_iterator_destroy to
 *  free memory used; it is important to note that the iterator is
 *  valid only as long as the policy is unchanged.
 *  @return Returns 0 on success, > 0 if the type is an attribute
 *  and < 0 on failure; if the call fails, errno will be set and
 *  *types will be NULL. If the type is an attribute *types will
 *  be NULL.
 */
	extern int qpol_type_get_attr_iter(const qpol_policy_t * policy, const qpol_type_t * datum, qpol_iterator_t ** attrs);

/**
 *  Get the name by which a type is identified from its datum.
 *  @param policy The policy associated with the type.
 *  @param datum The type for which to get the name.
 *  @param name Pointer in which to store the name; the caller
 *  should not free the string. If the type is an alias then the
 *  primary name will be returned.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *name will be NULL.
 */
	extern int qpol_type_get_name(const qpol_policy_t * policy, const qpol_type_t * datum, const char **name);

/**
 *  Get an iterator for the list of aliases for a type.  If the given
 *  type is an alias, this returns an iterator of its primary type's
 *  aliases.
 *  @param policy The policy associated with the type.
 *  @param datum The type for which to get aliases.
 *  @param aliases Iterator of type char* returned; the caller is
 *  responsible for calling qpol_iterator_destroy to free
 *  memory used; it is important to note that the iterator is valid
 *  only as long as the policy is unchanged. If a type has no aliases,
 *  the iterator will be at end and have size 0.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *aliases will be NULL.
 */
	extern int qpol_type_get_alias_iter(const qpol_policy_t * policy, const qpol_type_t * datum, qpol_iterator_t ** aliases);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_TYPE_QUERY_H */
