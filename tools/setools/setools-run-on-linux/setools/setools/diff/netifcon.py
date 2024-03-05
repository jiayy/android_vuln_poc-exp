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


modified_netifcon_record = namedtuple("modified_netifcon", ["rule",
                                                            "added_context",
                                                            "removed_context",
                                                            "added_packet",
                                                            "removed_packet"])


class NetifconsDifference(Difference):

    """Determine the difference in netifcons between two policies."""

    added_netifcons = DiffResultDescriptor("diff_netifcons")
    removed_netifcons = DiffResultDescriptor("diff_netifcons")
    modified_netifcons = DiffResultDescriptor("diff_netifcons")

    def diff_netifcons(self):
        """Generate the difference in netifcons between the policies."""

        self.log.info("Generating netifcon differences from {0.left_policy} to {0.right_policy}".
                      format(self))

        self.added_netifcons, self.removed_netifcons, matched_netifcons = self._set_diff(
            (NetifconWrapper(n) for n in self.left_policy.netifcons()),
            (NetifconWrapper(n) for n in self.right_policy.netifcons()))

        self.modified_netifcons = []

        for left_netifcon, right_netifcon in matched_netifcons:
            # Criteria for modified netifcons
            # 1. change to context
            # 2. change to packet context
            if ContextWrapper(left_netifcon.context) != ContextWrapper(right_netifcon.context):
                removed_context = left_netifcon.context
                added_context = right_netifcon.context
            else:
                removed_context = None
                added_context = None

            if ContextWrapper(left_netifcon.packet) != ContextWrapper(right_netifcon.packet):
                removed_packet = left_netifcon.packet
                added_packet = right_netifcon.packet
            else:
                removed_packet = None
                added_packet = None

            if removed_context or removed_packet:
                self.modified_netifcons.append(modified_netifcon_record(
                    left_netifcon, added_context, removed_context, added_packet, removed_packet))

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting netifcon differences")
        self.added_netifcons = None
        self.removed_netifcons = None
        self.modified_netifcons = None


class NetifconWrapper(Wrapper):

    """Wrap netifcon statements for diff purposes."""

    __slots__ = ("netif")

    def __init__(self, ocon):
        self.origin = ocon
        self.netif = ocon.netif
        self.key = hash(ocon)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.netif < other.netif

    def __eq__(self, other):
        return self.netif == other.netif
