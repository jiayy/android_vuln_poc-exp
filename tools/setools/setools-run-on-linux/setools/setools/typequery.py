# Copyright 2014-2015, Tresys Technology, LLC
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
import logging
import re

from .descriptors import CriteriaSetDescriptor
from .mixins import MatchAlias, MatchName
from .query import PolicyQuery
from .util import match_regex_or_set


class TypeQuery(MatchAlias, MatchName, PolicyQuery):

    """
    Query SELinux policy types.

    Parameter:
    policy              The policy to query.

    Keyword Parameters/Class attributes:
    name                The type name to match.
    name_regex          If true, regular expression matching
                        will be used on the type names.
    alias               The alias name to match.
    alias_regex         If true, regular expression matching
                        will be used on the alias names.
    attrs               The attribute to match.
    attrs_equal         If true, only types with attribute sets
                        that are equal to the criteria will
                        match.  Otherwise, any intersection
                        will match.
    attrs_regex         If true, regular expression matching
                        will be used on the attribute names instead
                        of set logic.
    permissive          The permissive state to match.  If this
                        is None, the state is not matched.
    """

    attrs = CriteriaSetDescriptor("attrs_regex", "lookup_typeattr")
    attrs_regex = False
    attrs_equal = False
    _permissive = None

    @property
    def permissive(self):
        return self._permissive

    @permissive.setter
    def permissive(self, value):
        if value is None:
            self._permissive = None
        else:
            self._permissive = bool(value)

    def __init__(self, policy, **kwargs):
        super(TypeQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self):
        """Generator which yields all matching types."""
        self.log.info("Generating type results from {0.policy}".format(self))
        self._match_name_debug(self.log)
        self._match_alias_debug(self.log)
        self.log.debug("Attrs: {0.attrs!r}, regex: {0.attrs_regex}, "
                       "eq: {0.attrs_equal}".format(self))
        self.log.debug("Permissive: {0.permissive}".format(self))

        for t in self.policy.types():
            if not self._match_name(t):
                continue

            if not self._match_alias(t):
                continue

            if self.attrs and not match_regex_or_set(
                    set(t.attributes()),
                    self.attrs,
                    self.attrs_equal,
                    self.attrs_regex):
                continue

            if self.permissive is not None and t.ispermissive != self.permissive:
                continue

            yield t
