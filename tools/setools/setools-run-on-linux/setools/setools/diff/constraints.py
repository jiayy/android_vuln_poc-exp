# Copyright 2016, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
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
from collections import namedtuple

from ..policyrep import ConstraintRuletype
from .descriptors import DiffResultDescriptor
from .difference import Difference, SymbolWrapper, Wrapper
from .objclass import class_wrapper_factory
from .types import type_wrapper_factory


class ConstraintsDifference(Difference):

    """
    Determine the difference in constraints between two policies.

    Since the compiler does not union constraints, there may be multiple
    constraints with the same ruletype, object class, and permission
    set, so constraints can only be added or removed, not modified.

    The constraint expressions are compared only on a basic level.
    Expressions that are logically equivalent but are structurally
    different, for example, by associativity, will be considered
    different.  Type and role attributes are also not expanded,
    so if there are changes to attribute members, it will not
    be reflected as a difference.
    """

    added_constrains = DiffResultDescriptor("diff_constrains")
    removed_constrains = DiffResultDescriptor("diff_constrains")

    added_mlsconstrains = DiffResultDescriptor("diff_mlsconstrains")
    removed_mlsconstrains = DiffResultDescriptor("diff_mlsconstrains")

    added_validatetrans = DiffResultDescriptor("diff_validatetrans")
    removed_validatetrans = DiffResultDescriptor("diff_validatetrans")

    added_mlsvalidatetrans = DiffResultDescriptor("diff_mlsvalidatetrans")
    removed_mlsvalidatetrans = DiffResultDescriptor("diff_mlsvalidatetrans")

    # Lists of rules for each policy
    _left_constrains = None
    _right_constrains = None

    _left_mlsconstrains = None
    _right_mlsconstrains = None

    _left_validatetrans = None
    _right_validatetrans = None

    _left_mlsvalidatetrans = None
    _right_mlsvalidatetrans = None

    def diff_constrains(self):
        """Generate the difference in constraint rules between the policies."""

        self.log.info("Generating constraint differences from {0.left_policy} to {0.right_policy}".
                      format(self))

        if self._left_constrains is None or self._right_constrains is None:
            self._create_constrain_lists()

        self.added_constrains, self.removed_constrains, _ = self._set_diff(
            (ConstraintWrapper(c) for c in self._left_constrains),
            (ConstraintWrapper(c) for c in self._right_constrains))

    def diff_mlsconstrains(self):
        """Generate the difference in MLS constraint rules between the policies."""

        self.log.info(
            "Generating MLS constraint differences from {0.left_policy} to {0.right_policy}".
            format(self))

        if self._left_mlsconstrains is None or self._right_mlsconstrains is None:
            self._create_constrain_lists()

        self.added_mlsconstrains, self.removed_mlsconstrains, _ = self._set_diff(
            (ConstraintWrapper(c) for c in self._left_mlsconstrains),
            (ConstraintWrapper(c) for c in self._right_mlsconstrains))

    def diff_validatetrans(self):
        """Generate the difference in validatetrans rules between the policies."""

        self.log.info(
            "Generating validatetrans differences from {0.left_policy} to {0.right_policy}".
            format(self))

        if self._left_validatetrans is None or self._right_validatetrans is None:
            self._create_constrain_lists()

        self.added_validatetrans, self.removed_validatetrans, _ = self._set_diff(
            (ConstraintWrapper(c) for c in self._left_validatetrans),
            (ConstraintWrapper(c) for c in self._right_validatetrans))

    def diff_mlsvalidatetrans(self):
        """Generate the difference in MLS validatetrans rules between the policies."""

        self.log.info(
            "Generating mlsvalidatetrans differences from {0.left_policy} to {0.right_policy}".
            format(self))

        if self._left_mlsvalidatetrans is None or self._right_mlsvalidatetrans is None:
            self._create_constrain_lists()

        self.added_mlsvalidatetrans, self.removed_mlsvalidatetrans, _ = self._set_diff(
            (ConstraintWrapper(c) for c in self._left_mlsvalidatetrans),
            (ConstraintWrapper(c) for c in self._right_mlsvalidatetrans))

    #
    # Internal functions
    #
    def _create_constrain_lists(self):
        """Create rule lists for both policies."""
        self._left_constrains = []
        self._left_mlsconstrains = []
        self._left_validatetrans = []
        self._left_mlsvalidatetrans = []
        for rule in self.left_policy.constraints():
            if rule.ruletype == ConstraintRuletype.constrain:
                self._left_constrains.append(rule)
            elif rule.ruletype == ConstraintRuletype.mlsconstrain:
                self._left_mlsconstrains.append(rule)
            elif rule.ruletype == ConstraintRuletype.validatetrans:
                self._left_validatetrans.append(rule)
            elif rule.ruletype == ConstraintRuletype.mlsvalidatetrans:
                self._left_mlsvalidatetrans.append(rule)
            else:
                self.log.error("Unknown rule type: {0} (This is an SETools bug)".
                               format(rule.ruletype))

        self._right_constrains = []
        self._right_mlsconstrains = []
        self._right_validatetrans = []
        self._right_mlsvalidatetrans = []
        for rule in self.right_policy.constraints():
            if rule.ruletype == ConstraintRuletype.constrain:
                self._right_constrains.append(rule)
            elif rule.ruletype == ConstraintRuletype.mlsconstrain:
                self._right_mlsconstrains.append(rule)
            elif rule.ruletype == ConstraintRuletype.validatetrans:
                self._right_validatetrans.append(rule)
            elif rule.ruletype == ConstraintRuletype.mlsvalidatetrans:
                self._right_mlsvalidatetrans.append(rule)
            else:
                self.log.error("Unknown rule type: {0} (This is an SETools bug)".
                               format(rule.ruletype))

    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting all constraints differences")
        self.added_constrains = None
        self.removed_constrains = None
        self.added_mlsconstrains = None
        self.removed_mlsconstrains = None
        self.added_validatetrans = None
        self.removed_validatetrans = None
        self.added_mlsvalidatetrans = None
        self.removed_mlsvalidatetrans = None

        # Sets of rules for each policy
        self._left_constrains = None
        self._left_mlsconstrains = None
        self._left_validatetrans = None
        self._left_mlsvalidatetrans = None
        self._right_constrains = None
        self._right_mlsconstrains = None
        self._right_validatetrans = None
        self._right_mlsvalidatetrans = None


class ConstraintWrapper(Wrapper):

    """Wrap constraints for diff purposes."""

    __slots__ = ("ruletype", "tclass", "perms", "expr")

    def __init__(self, rule):
        self.origin = rule
        self.ruletype = rule.ruletype
        self.tclass = class_wrapper_factory(rule.tclass)

        try:
            self.perms = rule.perms
        except AttributeError:
            # (mls)validatetrans
            self.perms = None

        self.key = hash(rule)

        self.expr = []
        for op in rule.expression:
            if isinstance(op, frozenset):
                # lists of types/users/roles
                self.expr.append(frozenset(SymbolWrapper(item) for item in op))
            else:
                # strings in the expression such as u1/r1/t1 or "=="
                self.expr.append(op)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        return self.ruletype == other.ruletype and \
            self.tclass == other.tclass and \
            self.perms == other.perms and \
            self.expr == other.expr
