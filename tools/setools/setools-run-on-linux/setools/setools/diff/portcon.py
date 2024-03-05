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


modified_portcon_record = namedtuple("modified_portcon", ["rule",
                                                          "added_context",
                                                          "removed_context"])


class PortconsDifference(Difference):

    """Determine the difference in portcons between two policies."""

    added_portcons = DiffResultDescriptor("diff_portcons")
    removed_portcons = DiffResultDescriptor("diff_portcons")
    modified_portcons = DiffResultDescriptor("diff_portcons")

    def diff_portcons(self):
        """Generate the difference in portcons between the policies."""

        self.log.info("Generating portcon differences from {0.left_policy} to {0.right_policy}".
                      format(self))

        self.added_portcons, self.removed_portcons, matched_portcons = self._set_diff(
            (PortconWrapper(n) for n in self.left_policy.portcons()),
            (PortconWrapper(n) for n in self.right_policy.portcons()))

        self.modified_portcons = []

        for left_portcon, right_portcon in matched_portcons:
            # Criteria for modified portcons
            # 1. change to context
            if ContextWrapper(left_portcon.context) != ContextWrapper(right_portcon.context):
                self.modified_portcons.append(modified_portcon_record(left_portcon,
                                                                      right_portcon.context,
                                                                      left_portcon.context))

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting portcon differences")
        self.added_portcons = None
        self.removed_portcons = None
        self.modified_portcons = None


class PortconWrapper(Wrapper):

    """Wrap portcon statements for diff purposes."""

    __slots__ = ("protocol", "low", "high")

    def __init__(self, ocon):
        self.origin = ocon
        self.protocol = ocon.protocol
        self.low, self.high = ocon.ports
        self.key = hash(ocon)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.origin < other.origin

    def __eq__(self, other):
        return self.protocol == other.protocol and \
            self.low == other.low and \
            self.high == other.high
