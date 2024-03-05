# Copyright 2015, Tresys Technology, LLC
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

from .descriptors import DiffResultDescriptor
from .difference import Difference, SymbolWrapper


modified_commons_record = namedtuple("modified_common", ["added_perms",
                                                         "removed_perms",
                                                         "matched_perms"])


class CommonDifference(Difference):

    """
    Determine the difference in common permission sets
    between two policies.
    """

    added_commons = DiffResultDescriptor("diff_commons")
    removed_commons = DiffResultDescriptor("diff_commons")
    modified_commons = DiffResultDescriptor("diff_commons")

    def diff_commons(self):
        """Generate the difference in commons between the policies."""

        self.log.info(
            "Generating common differences from {0.left_policy} to {0.right_policy}".format(self))

        self.added_commons, self.removed_commons, matched_commons = self._set_diff(
            (SymbolWrapper(c) for c in self.left_policy.commons()),
            (SymbolWrapper(c) for c in self.right_policy.commons()))

        self.modified_commons = dict()

        for left_common, right_common in matched_commons:
            # Criteria for modified commons
            # 1. change to permissions
            added_perms, removed_perms, matched_perms = self._set_diff(left_common.perms,
                                                                       right_common.perms,
                                                                       unwrap=False)

            if added_perms or removed_perms:
                self.modified_commons[left_common] = modified_commons_record(added_perms,
                                                                             removed_perms,
                                                                             matched_perms)

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting common differences")
        self.added_commons = None
        self.removed_commons = None
        self.modified_commons = None
