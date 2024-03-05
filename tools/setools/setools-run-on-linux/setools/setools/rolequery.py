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
from .mixins import MatchName
from .query import PolicyQuery
from .util import match_regex_or_set


class RoleQuery(MatchName, PolicyQuery):

    """
    Query SELinux policy roles.

    Parameter:
    policy            The policy to query.

    Keyword Parameters/Class attributes:
    name         The role name to match.
    name_regex   If true, regular expression matching
                 will be used on the role names.
    types        The type to match.
    types_equal  If true, only roles with type sets
                 that are equal to the criteria will
                 match.  Otherwise, any intersection
                 will match.
    types_regex  If true, regular expression matching
                 will be used on the type names instead
                 of set logic.
    """

    types = CriteriaSetDescriptor("types_regex", "lookup_type")
    types_equal = False
    types_regex = False

    def __init__(self, policy, **kwargs):
        super(RoleQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self):
        """Generator which yields all matching roles."""
        self.log.info("Generating role results from {0.policy}".format(self))
        self._match_name_debug(self.log)
        self.log.debug("Types: {0.types!r}, regex: {0.types_regex}, "
                       "eq: {0.types_equal}".format(self))

        for r in self.policy.roles():
            if not self._match_name(r):
                continue

            if self.types and not match_regex_or_set(
                    set(r.types()),
                    self.types,
                    self.types_equal,
                    self.types_regex):
                continue

            yield r
