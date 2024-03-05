# Copyright 2016, Tresys Technology, LLC
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

from .context import ContextWrapper
from .descriptors import DiffResultDescriptor
from .difference import Difference, Wrapper


modified_fsuse_record = namedtuple("modified_fsuse", ["rule",
                                                      "added_context",
                                                      "removed_context"])


class FSUsesDifference(Difference):

    """Determine the difference in fs_use_* rules between two policies."""

    added_fs_uses = DiffResultDescriptor("diff_fs_uses")
    removed_fs_uses = DiffResultDescriptor("diff_fs_uses")
    modified_fs_uses = DiffResultDescriptor("diff_fs_uses")

    def diff_fs_uses(self):
        """Generate the difference in fs_use rules between the policies."""

        self.log.info(
            "Generating fs_use_* differences from {0.left_policy} to {0.right_policy}".
            format(self))

        self.added_fs_uses, self.removed_fs_uses, matched = self._set_diff(
            (FSUseWrapper(fs) for fs in self.left_policy.fs_uses()),
            (FSUseWrapper(fs) for fs in self.right_policy.fs_uses()))

        self.modified_fs_uses = []

        for left_rule, right_rule in matched:
            # Criteria for modified rules
            # 1. change to context
            if ContextWrapper(left_rule.context) != ContextWrapper(right_rule.context):
                self.modified_fs_uses.append(modified_fsuse_record(left_rule,
                                                                   right_rule.context,
                                                                   left_rule.context))

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting fs_use_* rule differences")
        self.added_fs_uses = None
        self.removed_fs_uses = None
        self.modified_fs_uses = None


class FSUseWrapper(Wrapper):

    """Wrap fs_use_* rules to allow set operations."""

    __slots__ = ("ruletype", "fs", "context")

    def __init__(self, rule):
        self.origin = rule
        self.ruletype = rule.ruletype
        self.fs = rule.fs
        self.context = ContextWrapper(rule.context)
        self.key = hash(rule)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        return self.ruletype == other.ruletype and self.fs == other.fs
