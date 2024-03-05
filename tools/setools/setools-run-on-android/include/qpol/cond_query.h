/**
 * @file
 * Defines the public interface for searching and iterating over
 * conditionals
 *
 * @author Kevin Carr kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang jtang@tresys.com
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

#ifndef QPOL_COND_QUERY_H
#define QPOL_COND_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <qpol/policy.h>
#include <qpol/bool_query.h>
#include <qpol/iterator.h>

	typedef struct qpol_cond qpol_cond_t;
	typedef struct qpol_cond_expr_node qpol_cond_expr_node_t;

/**
 *  Get an iterator over all conditionals in a policy.
 *  It is an error to call this function if rules are not loaded.
 *  @param policy Policy from which to get the conditionals.
 *  @param iter Iterator over items of type qpol_cond_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used in this iterator.
 *  It is important to node that this iterator is only valid as long as
 *  the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_cond_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter);

/**
 *  Get an iterator over the nodes in a conditional expression.
 *  Each node represents a single token of the expression in RPN.
 *  @param policy The policy associated with the conditional.
 *  @param cond The conditional from which to get the expression.
 *  @param iter Iterator over items of type qpol_cond_expr_node_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used in this iterator.
 *  It is important to node that this iterator is only valid as long as
 *  the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_cond_get_expr_node_iter(const qpol_policy_t * policy, const qpol_cond_t * cond, qpol_iterator_t ** iter);

/* flags for conditional rules */
#define QPOL_COND_RULE_LIST    0x00000001
#define QPOL_COND_RULE_ENABLED 0x00000002

/**
 *  Get an iterator over all av rules in a conditional's true list
 *  of a rule type in rule_type_mask.
 *  @param policy The policy associated with the conditional.
 *  @param cond The conditional from which to get the rules.
 *  @param rule_type_mask Bitwise or'ed set of QPOL_RULE_* values
 *  (see avrule_query.h) to include.
 *  @param iter Iterator over items of type qpol_avrule_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_cond_get_av_true_iter(const qpol_policy_t * policy, const qpol_cond_t * cond, uint32_t rule_type_mask,
					      qpol_iterator_t ** iter);

/**
 *  Get an iterator over all type rules in a conditional's true list
 *  of a rule type in rule_type_mask.
 *  @param policy The policy associated with the conditional.
 *  @param cond The conditional from which to get the rules.
 *  @param rule_type_mask Bitwise or'ed set of QPOL_RULE_TYPE_* values
 *  (see terule_query.h) to include.
 *  @param iter Iterator over items of type qpol_terule_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_cond_get_te_true_iter(const qpol_policy_t * policy, const qpol_cond_t * cond, uint32_t rule_type_mask,
					      qpol_iterator_t ** iter);

/**
 *  Get an iterator over all av rules in a conditional's false list
 *  of a rule type in rule_type_mask.
 *  @param policy The policy associated with the conditional.
 *  @param cond The conditional from which to get the rules.
 *  @param rule_type_mask Bitwise or'ed set of QPOL_RULE_* values
 *  (see avrule_query.h) to include.
 *  @param iter Iterator over items of type qpol_avrule_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_cond_get_av_false_iter(const qpol_policy_t * policy, const qpol_cond_t * cond, uint32_t rule_type_mask,
					       qpol_iterator_t ** iter);

/**
 *  Get an iterator over all type rules in a conditional's false list
 *  of a rule type in rule_type_mask.
 *  @param policy The policy associated with the conditional.
 *  @param cond The conditional from which to get the rules.
 *  @param rule_type_mask Bitwise or'ed set of QPOL_RULE_TYPE_* values
 *  (see terule_query.h) to include.
 *  @param iter Iterator over items of type qpol_avrule_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long as
 *  the policy is unmodifed.
 *  @returm 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_cond_get_te_false_iter(const qpol_policy_t * policy, const qpol_cond_t * cond, uint32_t rule_type_mask,
					       qpol_iterator_t ** iter);

/**
 *  Evaluate the expression of a conditional using current boolean values
 *  in the policy.
 *  @param policy The policy associated with the conditional.
 *  @param cond The conditional to evaluate.
 *  @param is_true Integer in which to store the result of evaluating the
 *  the expression, will be 1 if true and 0 otherwise.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *is_true will be 0.
 */
	extern int qpol_cond_eval(const qpol_policy_t * policy, const qpol_cond_t * cond, uint32_t * is_true);

/* values identical to conditional.h in sepol */
#define QPOL_COND_EXPR_BOOL	1      /* plain bool */
#define QPOL_COND_EXPR_NOT	2      /* !bool */
#define QPOL_COND_EXPR_OR	3      /* bool || bool */
#define QPOL_COND_EXPR_AND	4      /* bool && bool */
#define QPOL_COND_EXPR_XOR	5      /* bool ^ bool */
#define QPOL_COND_EXPR_EQ	6      /* bool == bool */
#define QPOL_COND_EXPR_NEQ	7      /* bool != bool */

/**
 *  Get the type of an expression node.
 *  @param policy The policy associated with the conditional expression.
 *  @param node The node from which to get the expression type.
 *  @param expr_type Integer in which to store the expression type;
 *  the value will be one of QPOL_COND_EXPR_* above.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *expr_type will be 0.
 */
	extern int qpol_cond_expr_node_get_expr_type(const qpol_policy_t * policy, const qpol_cond_expr_node_t * node,
						     uint32_t * expr_type);

/**
 *  Get the boolean used in an expression node.  This is only valid
 *  when the node's expression type is QPOL_COND_EXPR_BOOL.
 *  @param policy The policy associated with the conditional experssion.
 *  @param node The node from which to get the boolean. It is an error
 *  to call this function if the node is not of type QPOL_COND_EXPR_BOOL.
 *  @param cond_bool Pointer in which to store the boolean.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *cond_bool will be NULL.
 */
	extern int qpol_cond_expr_node_get_bool(const qpol_policy_t * policy, const qpol_cond_expr_node_t * node,
						qpol_bool_t ** cond_bool);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_COND_QUERY_H */
