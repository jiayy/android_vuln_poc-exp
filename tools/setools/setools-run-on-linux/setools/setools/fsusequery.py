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

from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor
from .mixins import MatchContext
from .policyrep import FSUseRuletype
from .query import PolicyQuery
from .util import match_regex


class FSUseQuery(MatchContext, PolicyQuery):

    """
    Query fs_use_* statements.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    ruletype        The rule type(s) to match.
    fs              The criteria to match the file system type.
    fs_regex        If true, regular expression matching
                    will be used on the file system type.
    user            The criteria to match the context's user.
    user_regex      If true, regular expression matching
                    will be used on the user.
    role            The criteria to match the context's role.
    role_regex      If true, regular expression matching
                    will be used on the role.
    type_           The criteria to match the context's type.
    type_regex      If true, regular expression matching
                    will be used on the type.
    range_          The criteria to match the context's range.
    range_subset    If true, the criteria will match if it is a subset
                    of the context's range.
    range_overlap   If true, the criteria will match if it overlaps
                    any of the context's range.
    range_superset  If true, the criteria will match if it is a superset
                    of the context's range.
    range_proper    If true, use proper superset/subset operations.
                    No effect if not using set operations.
    """

    ruletype = CriteriaSetDescriptor(enum_class=FSUseRuletype)
    fs = CriteriaDescriptor("fs_regex")
    fs_regex = False

    def __init__(self, policy, **kwargs):
        super(FSUseQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self):
        """Generator which yields all matching fs_use_* statements."""
        self.log.info("Generating fs_use_* results from {0.policy}".format(self))
        self.log.debug("Ruletypes: {0.ruletype}".format(self))
        self.log.debug("FS: {0.fs!r}, regex: {0.fs_regex}".format(self))
        self._match_context_debug(self.log)

        for fsu in self.policy.fs_uses():
            if self.ruletype and fsu.ruletype not in self.ruletype:
                continue

            if self.fs and not match_regex(
                    fsu.fs,
                    self.fs,
                    self.fs_regex):
                continue

            if not self._match_context(fsu.context):
                continue

            yield fsu
