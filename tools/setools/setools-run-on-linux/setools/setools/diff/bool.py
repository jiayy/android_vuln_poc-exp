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
from collections import defaultdict, namedtuple

from .descriptors import DiffResultDescriptor
from .difference import Difference, SymbolWrapper


modified_bool_record = namedtuple("modified_boolean", ["added_state", "removed_state"])

_bool_cache = defaultdict(dict)


def boolean_wrapper(policy, boolean):
    """
    Wrap booleans from the specified policy.

    This caches results to prevent duplicate wrapper
    objects in memory.
    """
    try:
        return _bool_cache[policy][boolean]
    except KeyError:
        b = SymbolWrapper(boolean)
        _bool_cache[policy][boolean] = b
        return b


class BooleansDifference(Difference):

    """Determine the difference in type attributes between two policies."""

    added_booleans = DiffResultDescriptor("diff_booleans")
    removed_booleans = DiffResultDescriptor("diff_booleans")
    modified_booleans = DiffResultDescriptor("diff_booleans")

    def diff_booleans(self):
        """Generate the difference in type attributes between the policies."""

        self.log.info("Generating Boolean differences from {0.left_policy} to {0.right_policy}".
                      format(self))

        self.added_booleans, self.removed_booleans, matched_booleans = \
            self._set_diff(
                (SymbolWrapper(b) for b in self.left_policy.bools()),
                (SymbolWrapper(b) for b in self.right_policy.bools()))

        self.modified_booleans = dict()

        for left_boolean, right_boolean in matched_booleans:
            # Criteria for modified booleans
            # 1. change to default state
            if left_boolean.state != right_boolean.state:
                self.modified_booleans[left_boolean] = modified_bool_record(right_boolean.state,
                                                                            left_boolean.state)

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting Boolean differences")
        self.added_booleans = None
        self.removed_booleans = None
        self.modified_booleans = None
