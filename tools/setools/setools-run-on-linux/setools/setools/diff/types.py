# Copyright 2015, Tresys Technology, LLC
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
from .typeattr import typeattr_wrapper_factory

from ..policyrep import Type


modified_types_record = namedtuple("modified_type", ["added_attributes",
                                                     "removed_attributes",
                                                     "matched_attributes",
                                                     "modified_permissive",
                                                     "permissive",
                                                     "added_aliases",
                                                     "removed_aliases",
                                                     "matched_aliases"])

_types_cache = defaultdict(dict)


def type_wrapper_factory(type_):
    """
    Wrap types from the specified policy.

    This caches results to prevent duplicate wrapper
    objects in memory.
    """
    try:
        return _types_cache[type_.policy][type_]
    except KeyError:
        t = SymbolWrapper(type_)
        _types_cache[type_.policy][type_] = t
        return t


def type_or_attr_wrapper_factory(type_):
    """
    Wrap types or attributes from the specified policy.

    This caches results to prevent duplicate wrapper
    objects in memory.
    """
    if isinstance(type_, Type):
        return type_wrapper_factory(type_)
    else:
        return typeattr_wrapper_factory(type_)


class TypesDifference(Difference):

    """Determine the difference in types between two policies."""

    added_types = DiffResultDescriptor("diff_types")
    removed_types = DiffResultDescriptor("diff_types")
    modified_types = DiffResultDescriptor("diff_types")

    def diff_types(self):
        """Generate the difference in types between the policies."""

        self.log.info(
            "Generating type differences from {0.left_policy} to {0.right_policy}".format(self))

        self.added_types, self.removed_types, matched_types = self._set_diff(
            (SymbolWrapper(t) for t in self.left_policy.types()),
            (SymbolWrapper(t) for t in self.right_policy.types()))

        self.modified_types = dict()

        for left_type, right_type in matched_types:
            # Criteria for modified types
            # 1. change to attribute set, or
            # 2. change to alias set, or
            # 3. different permissive setting
            added_attr, removed_attr, matched_attr = self._set_diff(
                (SymbolWrapper(a) for a in left_type.attributes()),
                (SymbolWrapper(a) for a in right_type.attributes()))

            added_aliases, removed_aliases, matched_aliases = self._set_diff(left_type.aliases(),
                                                                             right_type.aliases(),
                                                                             unwrap=False)

            left_permissive = left_type.ispermissive
            right_permissive = right_type.ispermissive
            mod_permissive = left_permissive != right_permissive

            if added_attr or removed_attr or added_aliases or removed_aliases or mod_permissive:
                self.modified_types[left_type] = modified_types_record(added_attr,
                                                                       removed_attr,
                                                                       matched_attr,
                                                                       mod_permissive,
                                                                       left_permissive,
                                                                       added_aliases,
                                                                       removed_aliases,
                                                                       matched_aliases)

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting type differences")
        self.added_types = None
        self.removed_types = None
        self.modified_types = None
