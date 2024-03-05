# Copyright 2014-2016, Tresys Technology, LLC
# Copyright 2016-2018, Chris PeBenito <pebenito@ieee.org>
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#

#
# Classes
#
class ConstraintRuletype(PolicyEnum):

    """Enumeration of constraint types."""

    constrain = 1
    mlsconstrain = 2
    validatetrans = 3
    mlsvalidatetrans = 4


cdef class BaseConstraint(PolicyObject):

    """Base class for constraint rules."""

    cdef:
        readonly object ruletype
        readonly object tclass
        readonly ConstraintExpression expression

    @property
    def perms(self):
        raise NotImplementedError


cdef class Constraint(BaseConstraint):

    """A constraint rule (constrain/mlsconstrain)."""

    cdef readonly frozenset perms

    @staticmethod
    cdef factory(SELinuxPolicy policy, ObjClass tclass, sepol.constraint_node_t *symbol):
        """Factory function for creating Constraint objects."""
        cdef Constraint c = Constraint.__new__(Constraint)
        c.policy = policy
        c.key = <uintptr_t>symbol
        c.tclass = tclass
        c.perms = frozenset(PermissionVectorIterator.factory(policy, tclass, symbol.permissions))
        c.expression = ConstraintExpression.factory(policy, symbol.expr)
        c.ruletype = ConstraintRuletype.mlsconstrain if c.expression.mls \
            else ConstraintRuletype.constrain
        return c

    def statement(self):
        if len(self.perms) > 1:
            perms = "{{ {0} }}".format(' '.join(self.perms))
        else:
            # convert to list since sets cannot be indexed
            perms = list(self.perms)[0]

        return "{0.ruletype} {0.tclass} {1} ({0.expression}); ".format(self, perms)


cdef class Validatetrans(BaseConstraint):

    """A validatetrans rule (validatetrans/mlsvalidatetrans)."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, ObjClass tclass, sepol.constraint_node_t *symbol):
        """Factory function for creating Validatetrans objects."""
        cdef Validatetrans v = Validatetrans.__new__(Validatetrans)
        v.policy = policy
        v.key = <uintptr_t>symbol
        v.tclass = tclass
        v.expression = ConstraintExpression.factory(policy, symbol.expr)
        v.ruletype = ConstraintRuletype.mlsvalidatetrans if v.expression.mls else \
            ConstraintRuletype.validatetrans
        return v

    @property
    def perms(self):
        raise ConstraintUseError("{0} rules do not have permissions.".format(self.ruletype))

    def statement(self):
        return "{0.ruletype} {0.tclass} ({0.expression});".format(self)


cdef class ConstraintExpression(PolicyObject):

    """
    A a list-like object representing a constraint's expression.

    The expression is in postfix notation, as that is how it is stored in the policy.
    The string representation, however, is in infix notation, as that is how it
    is written by policy writers.
    """

    cdef:
        list _infix
        list _postfix
        readonly bint mls
        readonly frozenset users
        readonly frozenset roles
        readonly frozenset types

    # There is no levels attribute as specific
    # levels cannot be used in expressions, only
    # the l1, h1, etc. symbols

    @staticmethod
    cdef inline ConstraintExpression factory(SELinuxPolicy policy, sepol.constraint_expr_t *symbol):
        """Factory function for creating ConstraintExpression objects."""
        cdef:
            ConstraintExpression e = ConstraintExpression.__new__(ConstraintExpression)
            list users = []
            list roles = []
            list types = []
            ConstraintExprNode expr_node

        e.policy = policy

        e._postfix = []
        for expr_node in ConstraintExprIterator.factory(policy, symbol):
            if expr_node.mls:
                e.mls = 1

            if expr_node.types:
                types.extend(expr_node.names)
            elif expr_node.roles:
                roles.extend(expr_node.names)
            elif expr_node.users:
                users.extend(expr_node.names)

            e._postfix.extend(expr_node)

        e.users = frozenset(users)
        e.roles = frozenset(roles)
        e.types = frozenset(types)

        return e

    def __str__(self):
        cdef list ret = []
        for item in self.infix():
            if isinstance(item, frozenset):
                if len(item) > 1:
                    ret.append("{{ {0} }} ".format(" ".join(str(j) for j in item)))
                else:
                    ret.append("{0}".format(" ".join(str(j) for j in item)))
            else:
                ret.append(item)

        return " ".join(ret)

    def __getitem__(self, idx):
        return self._postfix[idx]

    def __eq__(self, other):
        return self._postfix == other

    def infix(self):
        """The expression as an infix notation list."""

        if self._infix is None:
            self._infix = []

            _precedence = {
                "not": 4,
                "and": 2,
                "or": 1,
                "==": 3,
                "!=": 3,
                "dom": 3,
                "domby": 3,
                "incomp": 3}

            _max_precedence = 4

            _operands = ["u1", "u2", "u3",
                         "r1", "r2", "r3",
                         "t1", "t2", "t3",
                         "l1", "l2",
                         "h1", "h2"]

            # sepol representation is in postfix notation.  This code
            # converts it to infix notation.  Parentheses are added
            # to ensure correct expressions, though they may end up
            # being overused.  Set previous operator at start to the
            # highest precedence (op) so if there is a single binary
            # operator, no parentheses are output
            stack = []
            prev_op_precedence = _max_precedence
            for op in self._postfix:
                if isinstance(op, frozenset) or op in _operands:
                    # operands
                    stack.append(op)
                else:
                    # operators
                    if op == "not":
                        # unary operator
                        operator = op
                        operand = stack.pop()
                        op_precedence = _precedence[op]
                        stack.append([operator, "(", operand, ")"])
                    else:
                        # binary operators
                        operand2 = stack.pop()
                        operand1 = stack.pop()
                        operator = op

                        # if previous operator is of higher precedence
                        # no parentheses are needed.
                        if _precedence[op] < prev_op_precedence:
                            stack.append([operand1, operator, operand2])
                        else:
                            stack.append(["(", operand1, operator, operand2, ")"])

                    prev_op_precedence = _precedence[op]

            self._infix = flatten_list(stack)

        return self._infix

    def statement(self):
        raise NoStatement


cdef class ConstraintExprNode(PolicyObject):

    """
    A node of the low-level constraint expression.

    This is an immutable list-like object that contains one node
    of a constraint in postfix notation, e.g.:

    ["u1", "u2", "=="]

    This is only used for initializing a ConstraintExpression
    object.
    """

    cdef:
        uint32_t expression_type
        uint32_t operator
        uint32_t _symbol_type
        frozenset _names
        list _expression
        # T/F this node is MLS
        bint mls
        # T/F this node has roles/types/users
        bint roles
        bint types
        bint users

    _expr_type_to_text = {
        sepol.CEXPR_NOT: "not",
        sepol.CEXPR_AND: "and",
        sepol.CEXPR_OR: "or"}

    _expr_op_to_text = {
        sepol.CEXPR_EQ: "==",
        sepol.CEXPR_NEQ: "!=",
        sepol.CEXPR_DOM: "dom",
        sepol.CEXPR_DOMBY: "domby",
        sepol.CEXPR_INCOMP: "incomp"}

    _sym_to_text = {
        sepol.CEXPR_USER: "u1",
        sepol.CEXPR_ROLE: "r1",
        sepol.CEXPR_TYPE: "t1",
        sepol.CEXPR_USER + sepol.CEXPR_TARGET: "u2",
        sepol.CEXPR_ROLE + sepol.CEXPR_TARGET: "r2",
        sepol.CEXPR_TYPE + sepol.CEXPR_TARGET: "t2",
        sepol.CEXPR_USER + sepol.CEXPR_XTARGET: "u3",
        sepol.CEXPR_ROLE + sepol.CEXPR_XTARGET: "r3",
        sepol.CEXPR_TYPE + sepol.CEXPR_XTARGET: "t3",
        sepol.CEXPR_L1L2: "l1",
        sepol.CEXPR_L1H2: "l1",
        sepol.CEXPR_H1L2: "h1",
        sepol.CEXPR_H1H2: "h1",
        sepol.CEXPR_L1H1: "l1",
        sepol.CEXPR_L2H2: "l2",
        sepol.CEXPR_L1L2 + sepol.CEXPR_TARGET: "l2",
        sepol.CEXPR_L1H2 + sepol.CEXPR_TARGET: "h2",
        sepol.CEXPR_H1L2 + sepol.CEXPR_TARGET: "l2",
        sepol.CEXPR_H1H2 + sepol.CEXPR_TARGET: "h2",
        sepol.CEXPR_L1H1 + sepol.CEXPR_TARGET: "h1",
        sepol.CEXPR_L2H2 + sepol.CEXPR_TARGET: "h2"}

    _role_syms = [sepol.CEXPR_ROLE,
                  sepol.CEXPR_ROLE + sepol.CEXPR_TARGET,
                  sepol.CEXPR_ROLE + sepol.CEXPR_XTARGET]

    _type_syms = [sepol.CEXPR_TYPE,
                  sepol.CEXPR_TYPE + sepol.CEXPR_TARGET,
                  sepol.CEXPR_TYPE + sepol.CEXPR_XTARGET]

    _user_syms = [sepol.CEXPR_USER,
                  sepol.CEXPR_USER + sepol.CEXPR_TARGET,
                  sepol.CEXPR_USER + sepol.CEXPR_XTARGET]

    @staticmethod
    cdef inline ConstraintExprNode factory(SELinuxPolicy policy, sepol.constraint_expr_t *symbol):
        """Factory function for creating ConstraintExprNode objects."""
        cdef ConstraintExprNode n = ConstraintExprNode.__new__(ConstraintExprNode)
        n.policy = policy
        n.key = <uintptr_t>symbol
        n.expression_type = symbol.expr_type
        n.operator = symbol.op

        #
        # Determine attributes of expression node
        #
        if symbol.expr_type in (sepol.CEXPR_ATTR, sepol.CEXPR_NAMES):
            n._symbol_type = symbol.attr

        try:
            n.mls = n.symbol_type >= sepol.CEXPR_L1L2

            if symbol.expr_type == sepol.CEXPR_NAMES:
                if n.symbol_type in n._role_syms:
                    n.roles = True
                    n._names = frozenset(r for r in RoleEbitmapIterator.factory(policy,
                                                                                &symbol.names))
                elif n.symbol_type in n._type_syms:
                    n.types = True
                    if policy.version > 28:
                        n._names = frozenset(t for t in
                                             TypeOrAttributeEbitmapIterator.factory_from_set(
                                                 policy, symbol.type_names))
                    else:
                        n._names = frozenset(t for t in TypeEbitmapIterator.factory(
                                             policy, &symbol.names))
                else:
                    n.users = True
                    n._names = frozenset(u for u in UserEbitmapIterator.factory(policy,
                                                                                &symbol.names))

        except AttributeError:
            pass

        #
        # Build expression
        #
        if n.expression_type == sepol.CEXPR_ATTR:
            # logical operator with symbols (e.g. u1 == u2)
            operand1 = n._sym_to_text[n.symbol_type]
            operand2 = n._sym_to_text[n.symbol_type + sepol.CEXPR_TARGET]
            operator = n._expr_op_to_text[n.operator]

            n._expression = [operand1, operand2, operator]

        elif n.expression_type == sepol.CEXPR_NAMES:
            # logical operator with type or attribute list (e.g. t1 == { spam_t eggs_t })
            operand1 = n._sym_to_text[n.symbol_type]
            operand2 = n.names
            operator = n._expr_op_to_text[n.operator]

            n._expression = [operand1, operand2, operator]

        else:
            # individual operators (and/or/not)
            n._expression = [n._expr_type_to_text[n.expression_type]]

        return n

    def __iter__(self):
        return iter(self._expression)

    def __contains__(self, item):
        return item in self._expression

    def __len__(self):
        return len(self._expression)

    def __getitem__(self, idx):
        return self._expression[idx]

    @property
    def names(self):
        if self._names is None:
            raise AttributeError("names")

        return self._names

    @property
    def symbol_type(self):
        if self._symbol_type is None:
            raise AttributeError("symbol_type")

        return self._symbol_type

    def statement(self):
        raise NoStatement


#
# Iterators
#
cdef class ConstraintIterator(PolicyIterator):

    """Constraint iterator."""

    cdef:
        sepol.constraint_node_t *head
        sepol.constraint_node_t *curr
        ObjClass tclass

    @staticmethod
    cdef factory(SELinuxPolicy policy, ObjClass tclass, sepol.constraint_node_t *head):
        """Constraint iterator factory."""
        c = ConstraintIterator()
        c.policy = policy
        c.head = head
        c.tclass = tclass
        c.reset()
        return c

    def __next__(self):
        if self.curr == NULL:
            raise StopIteration

        item = Constraint.factory(self.policy, self.tclass, self.curr)
        self.curr = self.curr.next
        return item

    def __len__(self):
        cdef:
            sepol.constraint_node_t *curr
            size_t count = 0

        curr = self.head
        while curr != NULL:
             count += 1
             curr = curr.next

        return count

    def reset(self):
        """Reset the iterator back to the start."""
        self.curr = self.head


cdef class ValidatetransIterator(ConstraintIterator):

    """Validatetrans iterator."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, ObjClass tclass, sepol.constraint_node_t *head):
        """Validatetrans iterator factory."""
        v = ValidatetransIterator()
        v.policy = policy
        v.head = head
        v.tclass = tclass
        v.reset()
        return v

    def __next__(self):
        if self.curr == NULL:
            raise StopIteration

        item = Validatetrans.factory(self.policy, self.tclass, self.curr)
        self.curr = self.curr.next
        return item


cdef class ConstraintExprIterator(PolicyIterator):

    """
    Constraint low-level expression iterator.

    This is only used for initializing a ConstraintExpression
    object.
    """

    cdef:
        sepol.constraint_expr_t *head
        sepol.constraint_expr_t *curr

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.constraint_expr_t *head):
        """Constraint expression iterator factory."""
        e = ConstraintExprIterator()
        e.policy = policy
        e.head = head
        e.reset()
        return e

    def __next__(self):
        if self.curr == NULL:
            raise StopIteration

        item = ConstraintExprNode.factory(self.policy, self.curr)
        self.curr = self.curr.next
        return item

    def __len__(self):
        cdef:
            sepol.constraint_expr_t *curr
            size_t count = 0

        curr = self.head
        while curr != NULL:
             count += 1
             curr = curr.next

        return count

    def reset(self):
        """Reset the iterator back to the start."""
        self.curr = self.head
