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

from .descriptors import DiffResultDescriptor
from .difference import Difference, SymbolWrapper, Wrapper


modified_default_record = namedtuple("modified_default", ["rule",
                                                          "added_default",
                                                          "removed_default",
                                                          "added_default_range",
                                                          "removed_default_range"])


class DefaultsDifference(Difference):

    """Determine the difference in default_* between two policies."""

    added_defaults = DiffResultDescriptor("diff_defaults")
    removed_defaults = DiffResultDescriptor("diff_defaults")
    modified_defaults = DiffResultDescriptor("diff_defaults")

    def diff_defaults(self):
        """Generate the difference in type defaults between the policies."""

        self.log.info(
            "Generating default_* differences from {0.left_policy} to {0.right_policy}".
            format(self))

        self.added_defaults, self.removed_defaults, matched_defaults = self._set_diff(
            (DefaultWrapper(d) for d in self.left_policy.defaults()),
            (DefaultWrapper(d) for d in self.right_policy.defaults()))

        self.modified_defaults = []

        for left_default, right_default in matched_defaults:
            # Criteria for modified defaults
            # 1. change to default setting
            # 2. change to default range

            if left_default.default != right_default.default:
                removed_default = left_default.default
                added_default = right_default.default
            else:
                removed_default = None
                added_default = None

            try:
                if left_default.default_range != right_default.default_range:
                    removed_default_range = left_default.default_range
                    added_default_range = right_default.default_range
                else:
                    removed_default_range = None
                    added_default_range = None
            except AttributeError:
                removed_default_range = None
                added_default_range = None

            if removed_default or removed_default_range:
                self.modified_defaults.append(
                    modified_default_record(left_default,
                                            added_default,
                                            removed_default,
                                            added_default_range,
                                            removed_default_range))

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting default_* differences")
        self.added_defaults = None
        self.removed_defaults = None
        self.modified_defaults = None


class DefaultWrapper(Wrapper):

    """Wrap default_* to allow comparisons."""

    __slots__ = ("ruletype", "tclass")

    def __init__(self, default):
        self.origin = default
        self.ruletype = default.ruletype
        self.tclass = SymbolWrapper(default.tclass)
        self.key = hash(default)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        return self.ruletype == other.ruletype and \
            self.tclass == other.tclass
