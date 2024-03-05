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

from .context import ContextWrapper
from .descriptors import DiffResultDescriptor
from .difference import Difference, Wrapper


modified_ibendportcon_record = namedtuple("modified_ibendportcon", ["rule",
                                                                    "added_context",
                                                                    "removed_context"])


class IbendportconsDifference(Difference):

    """Determine the difference in ibendportcons between two policies."""

    added_ibendportcons = DiffResultDescriptor("diff_ibendportcons")
    removed_ibendportcons = DiffResultDescriptor("diff_ibendportcons")
    modified_ibendportcons = DiffResultDescriptor("diff_ibendportcons")

    def diff_ibendportcons(self):
        """Generate the difference in ibendportcons between the policies."""

        self.log.info(
            "Generating ibendportcon differences from {0.left_policy} to {0.right_policy}".
            format(self))

        self.added_ibendportcons, self.removed_ibendportcons, matched_ibendportcons = \
            self._set_diff(
                (IbendportconWrapper(n) for n in self.left_policy.ibendportcons()),
                (IbendportconWrapper(n) for n in self.right_policy.ibendportcons()))

        self.modified_ibendportcons = []

        for left_ibep, right_ibep in matched_ibendportcons:
            # Criteria for modified ibendportcons
            # 1. change to context
            if ContextWrapper(left_ibep.context) != ContextWrapper(right_ibep.context):
                self.modified_ibendportcons.append(
                    modified_ibendportcon_record(left_ibep,
                                                 right_ibep.context,
                                                 left_ibep.context))

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting ibendportcon differences")
        self.added_ibendportcons = None
        self.removed_ibendportcons = None
        self.modified_ibendportcons = None


class IbendportconWrapper(Wrapper):

    """Wrap ibendportcon statements for diff purposes."""

    __slots__ = ("name", "port")

    def __init__(self, ocon):
        self.origin = ocon
        self.name = ocon.name
        self.port = ocon.port
        self.key = hash(ocon)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.origin < other.origin

    def __eq__(self, other):
        return self.name == other.name and \
            self.port == other.port
