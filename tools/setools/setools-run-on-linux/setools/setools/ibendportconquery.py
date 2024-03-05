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
import logging

from .mixins import MatchContext, MatchName
from .query import PolicyQuery
from .util import match_regex


class IbendportconQuery(MatchContext, MatchName, PolicyQuery):

    """
    Infiniband endport context query.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    name            The name of the network interface to match.
    name_regex      If true, regular expression matching will
                    be used for matching the name.
    port            The port number to match.
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

    port = None

    def __init__(self, policy, **kwargs):
        super(IbendportconQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self):
        """Generator which yields all matching ibendportcons."""
        self.log.info("Generating ibendportcon results from {0.policy}".format(self))
        self._match_name_debug(self.log)
        self.log.debug("Port: {0.port}".format(self))
        self._match_context_debug(self.log)

        for endport in self.policy.ibendportcons():
            if self.name and not match_regex(
                    endport.name,
                    self.name,
                    self.name_regex):
                continue

            if self.port is not None and self.port != endport.port:
                continue

            if not self._match_context(endport.context):
                continue

            yield endport
