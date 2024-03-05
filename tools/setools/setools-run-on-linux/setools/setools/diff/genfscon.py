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


modified_genfs_record = namedtuple("modified_genfs", ["rule",
                                                      "added_context",
                                                      "removed_context"])


class GenfsconsDifference(Difference):

    """Determine the difference in genfscon rules between two policies."""

    added_genfscons = DiffResultDescriptor("diff_genfscons")
    removed_genfscons = DiffResultDescriptor("diff_genfscons")
    modified_genfscons = DiffResultDescriptor("diff_genfscons")

    def diff_genfscons(self):
        """Generate the difference in genfscon rules between the policies."""

        self.log.info(
            "Generating genfscon differences from {0.left_policy} to {0.right_policy}".
            format(self))

        self.added_genfscons, self.removed_genfscons, matched = self._set_diff(
            (GenfsconWrapper(fs) for fs in self.left_policy.genfscons()),
            (GenfsconWrapper(fs) for fs in self.right_policy.genfscons()))

        self.modified_genfscons = []

        for left_rule, right_rule in matched:
            # Criteria for modified rules
            # 1. change to context
            if ContextWrapper(left_rule.context) != ContextWrapper(right_rule.context):
                self.modified_genfscons.append(modified_genfs_record(left_rule,
                                                                     right_rule.context,
                                                                     left_rule.context))

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting genfscon rule differences")
        self.added_genfscons = None
        self.removed_genfscons = None
        self.modified_genfscons = None


class GenfsconWrapper(Wrapper):

    """Wrap genfscon rules to allow set operations."""

    __slots__ = ("fs", "path", "filetype", "context")

    def __init__(self, rule):
        self.origin = rule
        self.fs = rule.fs
        self.path = rule.path
        self.filetype = rule.filetype
        self.context = ContextWrapper(rule.context)
        self.key = hash(rule)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        return self.fs == other.fs and \
            self.path == other.path and \
            self.filetype == other.filetype
