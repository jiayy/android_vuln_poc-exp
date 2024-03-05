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

from .mixins import MatchName, MatchPermission
from .query import PolicyQuery


class CommonQuery(MatchPermission, MatchName, PolicyQuery):

    """
    Query common permission sets.

    Parameter:
    policy       The policy to query.

    Keyword Parameters/Class attributes:
    name         The name of the common to match.
    name_regex   If true, regular expression matching will
                 be used for matching the name.
    perms        The permissions to match.
    perms_equal  If true, only commons with permission sets
                 that are equal to the criteria will
                 match.  Otherwise, any intersection
                 will match.
    perms_regex  If true, regular expression matching will be used
                 on the permission names instead of set logic.
    """

    def __init__(self, policy, **kwargs):
        super(CommonQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self):
        """Generator which yields all matching commons."""
        self.log.info("Generating common results from {0.policy}".format(self))
        self._match_name_debug(self.log)
        self._match_perms_debug(self.log)

        for com in self.policy.commons():
            if not self._match_name(com):
                continue

            if not self._match_perms(com):
                continue

            yield com
