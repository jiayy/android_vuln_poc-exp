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

from ..policyrep import BoundsRuletype
from .descriptors import DiffResultDescriptor
from .difference import Difference, Wrapper
from .types import type_wrapper_factory


modified_bounds_record = namedtuple("modified_bound", ["rule", "added_bound", "removed_bound"])


class BoundsDifference(Difference):

    """Determine the difference in *bounds between two policies."""

    added_typebounds = DiffResultDescriptor("diff_typebounds")
    removed_typebounds = DiffResultDescriptor("diff_typebounds")
    modified_typebounds = DiffResultDescriptor("diff_typebounds")

    # Lists of rules for each policy
    _left_typebounds = None
    _right_typebounds = None

    def diff_typebounds(self):
        """Generate the difference in typebound rules between the policies."""

        self.log.info("Generating typebounds differences from {0.left_policy} to {0.right_policy}".
                      format(self))

        if self._left_typebounds is None or self._right_typebounds is None:
            self._create_typebound_lists()

        self.added_typebounds, self.removed_typebounds, matched_typebounds = self._set_diff(
            (BoundsWrapper(c) for c in self._left_typebounds),
            (BoundsWrapper(c) for c in self._right_typebounds),
            key=lambda b: str(b.child))

        self.modified_typebounds = []

        for left_bound, right_bound in matched_typebounds:
            if type_wrapper_factory(left_bound.parent) != type_wrapper_factory(right_bound.parent):
                self.modified_typebounds.append(modified_bounds_record(
                    left_bound, right_bound.parent, left_bound.parent))

    #
    # Internal functions
    #
    def _create_typebound_lists(self):
        """Create rule lists for both policies."""
        self._left_typebounds = []
        for rule in self.left_policy.bounds():
            if rule.ruletype == BoundsRuletype.typebounds:
                self._left_typebounds.append(rule)
            else:
                self.log.error("Unknown rule type: {0} (This is an SETools bug)".
                               format(rule.ruletype))

        self._right_typebounds = []
        for rule in self.right_policy.bounds():
            if rule.ruletype == BoundsRuletype.typebounds:
                self._right_typebounds.append(rule)
            else:
                self.log.error("Unknown rule type: {0} (This is an SETools bug)".
                               format(rule.ruletype))

    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting all *bounds differences")
        self.added_typebounds = None
        self.removed_typebounds = None

        # Sets of rules for each policy
        self._left_typebounds = None
        self._right_typebounds = None


class BoundsWrapper(Wrapper):

    """Wrap *bounds for diff purposes."""

    __slots__ = ("ruletype", "parent", "child")

    def __init__(self, rule):
        self.origin = rule
        self.ruletype = rule.ruletype
        self.parent = type_wrapper_factory(rule.parent)
        self.child = type_wrapper_factory(rule.child)
        self.key = hash(rule)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        return self.ruletype == other.ruletype and \
            self.child == other.child
