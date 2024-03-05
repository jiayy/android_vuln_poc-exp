/**
 * @file
 * Defines the public interface for searching and iterating over
 * constraints
 *
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

#ifndef QPOL_CONSTRAINT_QUERY_H
#define QPOL_CONSTRAINT_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <qpol/policy.h>
#include <qpol/iterator.h>
#include <qpol/class_perm_query.h>

	typedef struct qpol_constraint qpol_constraint_t;
	typedef struct qpol_validatetrans qpol_validatetrans_t;
	typedef struct qpol_constraint_expr_node qpol_constraint_expr_node_t;

/**
 *  Get an iterator for the constraints in a policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_constraint_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator. <b>The caller must also call free()
 *  on items returned by qpol_iterator_get_item() when using this iterator.</b>
 *  It is important to note that this iterator is only valid as long 
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_constraint_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter);

/**
 *  Get the object class from a constraint.
 *  @param policy The policy associated with the constraint.
 *  @param constr The constraint from which to get the class.
 *  @param obj_class Pointer in which to store the object class.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *obj_class will be NULL.
 */
	extern int qpol_constraint_get_class(const qpol_policy_t * policy, const qpol_constraint_t * constr,
					     const qpol_class_t ** obj_class);

/**
 *  Get an iterator over the permissions in a constraint.
 *  @param policy The policy from which the constraint comes.
 *  @param constr The constraint from which to get the permissions.
 *  @param iter Iterator over items of type char*.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator. The caller <b>should call</b>
 *  <b>free() on the strings returned by qpol_iterator_get_item().</b>
 *  It is important to note that this iterator is only valid as long 
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_constraint_get_perm_iter(const qpol_policy_t * policy, const qpol_constraint_t * constr,
						 qpol_iterator_t ** iter);

/**
 *  Get an iterator over the nodes in a constraint expression.
 *  @param policy The policy from which the constraint comes.
 *  @param constr The constraint from which to get the expression.
 *  @param iter Iterator over items of type qpol_constraint_expr_node_t.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator. The caller should not
 *  free the items returned by qpol_iterator_get_item().
 *  It is important to note that this iterator is only valid as long 
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_constraint_get_expr_iter(const qpol_policy_t * policy, const qpol_constraint_t * constr,
						 qpol_iterator_t ** iter);

/**
 *  Get an iterator for the validatetrans statements in a policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_validatetrans_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator. <b>The caller must also call free()
 *  on items returned by qpol_iterator_get_item() when using this iterator.</b>
 *  It is important to note that this iterator is only valid as long 
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_validatetrans_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter);

/**
 *  Get the object class from a validatetrans statement.
 *  @param policy The policy associated with the validatetrans statement.
 *  @param vtrans The validatetrans statement from which to get the class.
 *  @param obj_class Pointer in which to store the object class.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *obj_class will be NULL.
 */
	extern int qpol_validatetrans_get_class(const qpol_policy_t * policy, const qpol_validatetrans_t * vtrans,
						const qpol_class_t ** obj_class);

/**
 *  Get an iterator over the nodes in a validatetrans expression.
 *  @param policy The policy from which the validatetrans statement comes.
 *  @param vtrans The validatetrans statement from which to get the expression.
 *  @param iter Iterator over items of type qpol_constraint_expr_node_t.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator. The caller should not
 *  free the items returned by qpol_iterator_get_item().
 *  It is important to note that this iterator is only valid as long 
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_validatetrans_get_expr_iter(const qpol_policy_t * policy, const qpol_validatetrans_t * vtrans,
						    qpol_iterator_t ** iter);

/* expr_type values */
#define QPOL_CEXPR_TYPE_NOT   1
#define QPOL_CEXPR_TYPE_AND   2
#define QPOL_CEXPR_TYPE_OR    3
#define QPOL_CEXPR_TYPE_ATTR  4
#define QPOL_CEXPR_TYPE_NAMES 5

/**
 *  Get the code for the expression type of by an expression node.
 *  @patam policy The policy from which the expression comes.
 *  @param expr The expression node from which to get the expression type.
 *  @param expr_type Integer in which to store the expression type; the value
 *  will be one of QPOL_CEXPR_TYPE_* above.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *op will be 0.
 */
	extern int qpol_constraint_expr_node_get_expr_type(const qpol_policy_t * policy, const qpol_constraint_expr_node_t * expr,
							   uint32_t * expr_type);

/* attr values */
#define QPOL_CEXPR_SYM_USER       1
#define QPOL_CEXPR_SYM_ROLE       2
#define QPOL_CEXPR_SYM_TYPE       4
#define QPOL_CEXPR_SYM_TARGET     8
#define QPOL_CEXPR_SYM_XTARGET   16
#define QPOL_CEXPR_SYM_L1L2      32
#define QPOL_CEXPR_SYM_L1H2      64
#define QPOL_CEXPR_SYM_H1L2     128
#define QPOL_CEXPR_SYM_H1H2     256
#define QPOL_CEXPR_SYM_L1H1     512
#define QPOL_CEXPR_SYM_L2H2    1024

/**
 *  Get the code for the symbol type used by an expression node.
 *  @param policy The policy from which the expression comes.
 *  @param expr The expression node from which to get the symbol type.
 *  Must be of expression type QPOL_CEXPR_TYPE_ATTR or QPOL_CEXPR_TYPE_NAMES.
 *  @param sym_type Integer in which to store the symbol type; the value
 *  will be a bitwise or'ed set of QPOL_CEXPR_SYM_* above.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *sym_type will be 0.
 */
	extern int qpol_constraint_expr_node_get_sym_type(const qpol_policy_t * policy, const qpol_constraint_expr_node_t * expr,
							  uint32_t * sym_type);

/* op values */
#define QPOL_CEXPR_OP_EQ     1
#define QPOL_CEXPR_OP_NEQ    2
#define QPOL_CEXPR_OP_DOM    3
#define QPOL_CEXPR_OP_DOMBY  4
#define QPOL_CEXPR_OP_INCOMP 5

/**
 *  Get the operator used by an expression node.
 *  @param policy The policy from which the expression comes.
 *  @param expr The expression node from which to get the operator.
 *  Must be of expression type QPOL_CEXPR_TYPE_ATTR or QPOL_CEXPR_TYPE_NAMES.
 *  @param op Integer in which to store the operator; the value
 *  will be one of QPOL_CEXPR_OP_* above.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *op will be 0.
 */
	extern int qpol_constraint_expr_node_get_op(const qpol_policy_t * policy, const qpol_constraint_expr_node_t * expr,
						    uint32_t * op);

/**
 *  Get an iterator of the names in an expression node.
 *  @param policy The policy from which the expression comes.
 *  @param expr The expression node from which to create the iterator.
 *  Must be of expression type QPOL_CEXPR_TYPE_NAMES.
 *  @param iter Iterator over items of type char* returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator. <b>The caller should call
 *  free() on the strings returned by qpol_iterator_get_item().</b>
 *  It is important to note that this iterator is only valid as long 
 *  as the policy is unmodified.
 *  In the case where the symbol names are types, the name of a subtracted
 *  type will be prepended with a '-' character.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_constraint_expr_node_get_names_iter(const qpol_policy_t * policy, const qpol_constraint_expr_node_t * expr,
							    qpol_iterator_t ** iter);

/**
 *  Get an iterator for the constraints on a class.
 *  @param policy The policy associated with the class.
 *  @param obj_class The class from which to create the iterator.
 *  @param constr Iterator over items of type qpol_constraint_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator. <b>The caller must also call free()
 *  on items returned by qpol_iterator_get_item() when using this iterator.</b>
 *  It is important to note that this iterator is only valid as long 
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *constr will be NULL.
 */
	extern int qpol_class_get_constraint_iter(const qpol_policy_t * policy, const qpol_class_t * obj_class,
						  qpol_iterator_t ** constr);

/**
 *  Get an iterator for the validatetrans statements for a class.
 *  @param policy The policy associated with the class.
 *  @param obj_class The class from which to create the iterator.
 *  @param vtrans Iterator over items of type qpol_validatetrans_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy()
 *  to free memory used by this iterator. <b>The caller must also call free()
 *  on items returned by qpol_iterator_get_item() when using this iterator.</b>
 *  It is important to note that this iterator is only valid as long 
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *vtrans will be NULL.
 */
	extern int qpol_class_get_validatetrans_iter(const qpol_policy_t * policy, const qpol_class_t * obj_class,
						     qpol_iterator_t ** vtrans);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_CONSTRAINT_QUERY_H */
