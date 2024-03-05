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


modified_ibpkeycon_record = namedtuple("modified_ibpkeycon", ["rule",
                                                              "added_context",
                                                              "removed_context"])


class IbpkeyconsDifference(Difference):

    """Determine the difference in ibpkeycons between two policies."""

    added_ibpkeycons = DiffResultDescriptor("diff_ibpkeycons")
    removed_ibpkeycons = DiffResultDescriptor("diff_ibpkeycons")
    modified_ibpkeycons = DiffResultDescriptor("diff_ibpkeycons")

    def diff_ibpkeycons(self):
        """Generate the difference in ibpkeycons between the policies."""

        self.log.info(
            "Generating ibpkeycon differences from {0.left_policy} to {0.right_policy}".
            format(self))

        self.added_ibpkeycons, self.removed_ibpkeycons, matched_ibpkeycons = \
            self._set_diff(
                (IbpkeyconWrapper(n) for n in self.left_policy.ibpkeycons()),
                (IbpkeyconWrapper(n) for n in self.right_policy.ibpkeycons()))

        self.modified_ibpkeycons = []

        for left_ibpkey, right_ibpkey in matched_ibpkeycons:
            # Criteria for modified ibpkeycons
            # 1. change to context
            if ContextWrapper(left_ibpkey.context) != ContextWrapper(right_ibpkey.context):
                self.modified_ibpkeycons.append(
                    modified_ibpkeycon_record(left_ibpkey,
                                              right_ibpkey.context,
                                              left_ibpkey.context))

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting ibpkeycon differences")
        self.added_ibpkeycons = None
        self.removed_ibpkeycons = None
        self.modified_ibpkeycons = None


class IbpkeyconWrapper(Wrapper):

    """Wrap ibpkeycon statements for diff purposes."""

    __slots__ = ("subnet_prefix", "low", "high")

    def __init__(self, ocon):
        self.origin = ocon
        self.subnet_prefix = ocon.subnet_prefix
        self.low, self.high = ocon.pkeys
        self.key = hash(ocon)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.origin < other.origin

    def __eq__(self, other):
        return self.subnet_prefix == other.subnet_prefix and \
            self.low == other.low and \
            self.high == other.high
