/**
 *  @file
 *  Defines public interface for iterating over FTRULE rules.
 *
 *  @author Kevin Carr kcarr@tresys.com
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

#ifndef QPOL_FTRULE_QUERY
#define QPOL_FTRULE_QUERY

#ifdef	__cplusplus
extern "C"
{
#endif

#include <qpol/policy.h>
#include <qpol/iterator.h>

	typedef struct qpol_filename_trans qpol_filename_trans_t;

/**
 *  Get an iterator over all filename transition rules in the policy.
 *  @param policy Policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_filename_trans_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_filename_trans_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter);

/**
 *  Get the source type from a filename transition rule.
 *  @param policy The policy from which the rule comes.
 *  @param rule The rule from which to get the source type.
 *  @param source Pointer in which to store the source type.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *source will be NULL.
 */
	extern int qpol_filename_trans_get_source_type(const qpol_policy_t * policy, const qpol_filename_trans_t * rule,
						   const qpol_type_t ** source);

/**
 *  Get the target type from a filename transition rule.
 *  @param policy The policy from which the rule comes.
 *  @param rule The rule from which to get the target type.
 *  @param target Pointer in which to store the target type.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *target will be NULL.
 */
	extern int qpol_filename_trans_get_target_type(const qpol_policy_t * policy, const qpol_filename_trans_t * rule,
						   const qpol_type_t ** target);

/**
 *  Get the default type from a filename transition rule.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the default type.
 *  @param dflt Pointer in which to store the default type.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *dflt will be NULL.
 */
	extern int qpol_filename_trans_get_default_type(const qpol_policy_t * policy, const qpol_filename_trans_t * rule,
						const qpol_type_t ** dflt);

/**
 *  Get the object class from a filename transition rule.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the object class.
 *  @param obj_class Pointer in which to store the object class.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *obj_class will be NULL.
 */
	extern int qpol_filename_trans_get_object_class(const qpol_policy_t * policy, const qpol_filename_trans_t * rule,
						const qpol_class_t ** obj_class);

/**
 *  Get the filename from a filename transition rule.
 *  @param policy Policy from which the rule comes.
 *  @param rule The rule from which to get the transition filename.
 *  @param target Pointer in which to store the filename.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *target will be NULL.
 */
	extern int qpol_filename_trans_get_filename(const qpol_policy_t * policy, const qpol_filename_trans_t * rule,
						       const char ** name);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_FTRULE_QUERY */
