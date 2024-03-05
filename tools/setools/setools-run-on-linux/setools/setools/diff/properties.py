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
from .difference import Difference


modified_properties_record = namedtuple("modified_property", ["property", "added", "removed"])


class PropertiesDifference(Difference):

    """
    Determine the difference in policy properties
    (unknown permissions, MLS, etc.) between two policies.
    """

    modified_properties = DiffResultDescriptor("diff_properties")

    def diff_properties(self):
        self.modified_properties = []

        if self.left_policy.handle_unknown != self.right_policy.handle_unknown:
            self.modified_properties.append(
                modified_properties_record("handle_unknown",
                                           self.right_policy.handle_unknown,
                                           self.left_policy.handle_unknown))

        if self.left_policy.mls != self.right_policy.mls:
            self.modified_properties.append(
                modified_properties_record("MLS",
                                           self.right_policy.mls,
                                           self.left_policy.mls))

        if self.left_policy.version != self.right_policy.version:
            self.modified_properties.append(
                modified_properties_record("version",
                                           self.right_policy.version,
                                           self.left_policy.version))

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting property differences")
        self.modified_properties = None
