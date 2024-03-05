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
from .difference import Difference, SymbolWrapper


modified_initsids_record = namedtuple("modified_initsid", ["added_context", "removed_context"])


class InitialSIDsDifference(Difference):

    """Determine the difference in initsids between two policies."""

    added_initialsids = DiffResultDescriptor("diff_initialsids")
    removed_initialsids = DiffResultDescriptor("diff_initialsids")
    modified_initialsids = DiffResultDescriptor("diff_initialsids")

    def diff_initialsids(self):
        """Generate the difference in initial SIDs between the policies."""

        self.log.info("Generating initial SID differences from {0.left_policy} to {0.right_policy}".
                      format(self))

        self.added_initialsids, self.removed_initialsids, matched_initialsids = self._set_diff(
            (SymbolWrapper(i) for i in self.left_policy.initialsids()),
            (SymbolWrapper(i) for i in self.right_policy.initialsids()))

        self.modified_initialsids = dict()

        for left_initialsid, right_initialsid in matched_initialsids:
            # Criteria for modified initialsids
            # 1. change to context
            if ContextWrapper(left_initialsid.context) != ContextWrapper(right_initialsid.context):
                self.modified_initialsids[left_initialsid] = modified_initsids_record(
                    right_initialsid.context, left_initialsid.context)

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting initialsid differences")
        self.added_initialsids = None
        self.removed_initialsids = None
        self.modified_initialsids = None
