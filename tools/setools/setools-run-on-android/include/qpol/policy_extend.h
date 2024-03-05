/**
 *  @file
 *  Public interface for loading and using an extended
 *  policy image.
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

#ifndef QPOL_POLICY_EXTEND_H
#define QPOL_POLICY_EXTEND_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <qpol/policy.h>
#include <qpol/iterator.h>

/**
 *  Build the table of syntactic rules for a policy.
 *  Subsequent calls to this function have no effect.
 *  @param policy The policy for which to build the table.
 *  This policy will be modified by this call.
 *  @return 0 on success and < 0 on error; if the call fails,
 *  errno will be set.
 */
	extern int qpol_policy_build_syn_rule_table(qpol_policy_t * policy);

/* forward declarations: see avrule_query.h and terule_query.h */
	struct qpol_avrule;
	struct qpol_terule;

/**
 *  Get an iterator over the syntactic rules contributing to an av rule.
 *  @param policy Policy associated with the rule.
 *  @param rule Rule from which to get the syntactic rules.
 *  @param iter Iterator over items of type qpol_syn_avrule_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_avrule_get_syn_avrule_iter(const qpol_policy_t * policy, const struct qpol_avrule *rule,
						   qpol_iterator_t ** iter);

/**
 *  Get an iterator over the syntactic rules contributing to a type rule.
 *  @param policy Policy associated with the rule.
 *  @param rule Rule from which to get the syntactic rules.
 *  @param iter Iterator over items of type qpol_syn_terule_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_terule_get_syn_terule_iter(const qpol_policy_t * policy, const struct qpol_terule *rule,
						   qpol_iterator_t ** iter);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_POLICY_EXTEND_H */
