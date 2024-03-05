# Derived from portconquery.py
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

from .mixins import MatchContext
from .policyrep import IomemconRange
from .query import PolicyQuery
from .util import match_range


class IomemconQuery(MatchContext, PolicyQuery):

    """
    Iomemcon context query.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    addr            A 2-tuple of the memory addr range to match. (Set both to
                    the same value for a single mem addr)
    addr_subset     If true, the criteria will match if it is a subset
                    of the iomemcon's range.
    addr_overlap    If true, the criteria will match if it overlaps
                    any of the iomemcon's range.
    addr_superset   If true, the criteria will match if it is a superset
                    of the iomemcon's range.
    addr_proper     If true, use proper superset/subset operations.
                    No effect if not using set operations.

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

    _addr = None
    addr_subset = False
    addr_overlap = False
    addr_superset = False
    addr_proper = False

    @property
    def addr(self):
        return self._addr

    @addr.setter
    def addr(self, value):
        pending_addr = IomemconRange(*value)

        if all(pending_addr):
            if pending_addr.low < 1 or pending_addr.high < 1:
                raise ValueError("Memory address must be positive: {0.low}-{0.high}".
                                 format(pending_addr))

            if pending_addr.low > pending_addr.high:
                raise ValueError(
                    "The low mem addr must be smaller than the high mem addr: {0.low}-{0.high}".
                    format(pending_addr))

            self._addr = pending_addr
        else:
            self._addr = None

    def __init__(self, policy, **kwargs):
        super(IomemconQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self):
        """Generator which yields all matching iomemcons."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Address: {0.addr!r}, overlap: {0.addr_overlap}, "
                       "subset: {0.addr_subset}, superset: {0.addr_superset}, "
                       "proper: {0.addr_proper}".format(self))
        self._match_context_debug(self.log)

        for iomemcon in self.policy.iomemcons():

            if self.addr and not match_range(
                    iomemcon.addr,
                    self.addr,
                    self.addr_subset,
                    self.addr_overlap,
                    self.addr_superset,
                    self.addr_proper):
                continue

            if not self._match_context(iomemcon.context):
                continue

            yield iomemcon
