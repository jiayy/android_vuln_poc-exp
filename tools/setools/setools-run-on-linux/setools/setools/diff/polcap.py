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
from .descriptors import DiffResultDescriptor
from .difference import Difference, SymbolWrapper


class PolCapsDifference(Difference):

    """Determine the difference in polcaps between two policies."""

    added_polcaps = DiffResultDescriptor("diff_polcaps")
    removed_polcaps = DiffResultDescriptor("diff_polcaps")

    def diff_polcaps(self):
        """Generate the difference in polcaps between the policies."""

        self.log.info("Generating policy cap differences from {0.left_policy} to {0.right_policy}".
                      format(self))

        self.added_polcaps, self.removed_polcaps, _ = self._set_diff(
            (SymbolWrapper(n) for n in self.left_policy.polcaps()),
            (SymbolWrapper(n) for n in self.right_policy.polcaps()))

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting policy capability differences")
        self.added_polcaps = None
        self.removed_polcaps = None
