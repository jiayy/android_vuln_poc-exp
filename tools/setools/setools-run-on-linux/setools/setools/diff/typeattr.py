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


modified_typeattr_record = namedtuple("modified_typeattr", ["added_types",
                                                            "removed_types",
                                                            "matched_types"])

_typeattr_cache = defaultdict(dict)


def typeattr_wrapper_factory(attr):
    """
    Wrap type attributes from the specified policy.

    This caches results to prevent duplicate wrapper
    objects in memory.
    """
    try:
        return _typeattr_cache[attr.policy][attr]
    except KeyError:
        a = SymbolWrapper(attr)
        _typeattr_cache[attr.policy][attr] = a
        return a


class TypeAttributesDifference(Difference):

    """Determine the difference in type attributes between two policies."""

    added_type_attributes = DiffResultDescriptor("diff_type_attributes")
    removed_type_attributes = DiffResultDescriptor("diff_type_attributes")
    modified_type_attributes = DiffResultDescriptor("diff_type_attributes")

    def diff_type_attributes(self):
        """Generate the difference in type attributes between the policies."""

        self.log.info(
            "Generating type attribute differences from {0.left_policy} to {0.right_policy}".
            format(self))

        self.added_type_attributes, self.removed_type_attributes, matched_attributes = \
            self._set_diff(
                (SymbolWrapper(r) for r in self.left_policy.typeattributes()),
                (SymbolWrapper(r) for r in self.right_policy.typeattributes()))

        self.modified_type_attributes = dict()

        for left_attribute, right_attribute in matched_attributes:
            # Criteria for modified attributes
            # 1. change to type set
            added_types, removed_types, matched_types = self._set_diff(
                (SymbolWrapper(t) for t in left_attribute.expand()),
                (SymbolWrapper(t) for t in right_attribute.expand()))

            if added_types or removed_types:
                self.modified_type_attributes[left_attribute] = modified_typeattr_record(
                    added_types, removed_types, matched_types)

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting type attribute differences")
        self.added_type_attributes = None
        self.removed_type_attributes = None
        self.modified_type_attributes = None
