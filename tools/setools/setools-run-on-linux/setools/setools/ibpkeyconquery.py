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
import ipaddress
import logging

from .mixins import MatchContext
from .policyrep import IbpkeyconRange
from .query import PolicyQuery
from .util import match_range


class IbpkeyconQuery(MatchContext, PolicyQuery):

    """
    Infiniband pkey context query.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    subnet_prefix   A subnet prefix to match.
    pkeys           A 2-tuple of the pkey range to match. (Set both to
                    the same value for a single pkey)
    pkeys_subset    If true, the criteria will match if it is a subset
                    of the ibpkeycon's range.
    pkeys_overlap   If true, the criteria will match if it overlaps
                    any of the ibpkeycon's range.
    pkeys_superset  If true, the criteria will match if it is a superset
                    of the ibpkeycon's range.
    pkeys_proper    If true, use proper superset/subset operations.
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

    _subnet_prefix = None
    _pkeys = None
    pkeys_subset = False
    pkeys_overlap = False
    pkeys_superset = False
    pkeys_proper = False

    def __init__(self, policy, **kwargs):
        super(IbpkeyconQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    @property
    def pkeys(self):
        return self._pkeys

    @pkeys.setter
    def pkeys(self, value):
        if value is not None:
            pending_pkeys = IbpkeyconRange(*value)

            if pending_pkeys.low < 1 or pending_pkeys.high < 1:
                raise ValueError("Pkeys must be positive: {0.low:#x}-{0.high:#x}".
                                 format(pending_pkeys))

            if pending_pkeys.low > 0xffff or pending_pkeys.high > 0xffff:
                raise ValueError("Pkeys maximum is 0xffff: {0.low:#x}-{0.high:#x}".
                                 format(pending_pkeys))

            if pending_pkeys.low > pending_pkeys.high:
                raise ValueError(
                    "The low pkey must be smaller than the high pkey: {0.low:#x}-{0.high:#x}".
                    format(pending_pkeys))

            self._pkeys = pending_pkeys
        else:
            self._pkeys = None

    @property
    def subnet_prefix(self):
        return self._subnet_prefix

    @subnet_prefix.setter
    def subnet_prefix(self, value):
        if value:
            self._subnet_prefix = ipaddress.IPv6Address(value)
        else:
            self._subnet_prefix = None

    def results(self):
        """Generator which yields all matching ibpkeycons."""
        self.log.info("Generating ibpkeycon results from {0.policy}".format(self))
        self.log.debug("Subnet Prefix: {0.subnet_prefix}".format(self))
        self.log.debug("Pkeys: {0.pkeys}, overlap: {0.pkeys_overlap}, "
                       "subset: {0.pkeys_subset}, superset: {0.pkeys_superset}, "
                       "proper: {0.pkeys_proper}".format(self))
        self._match_context_debug(self.log)

        for pk in self.policy.ibpkeycons():
            if self.subnet_prefix is not None and self.subnet_prefix != pk.subnet_prefix:
                continue

            if self.pkeys and not match_range(
                    pk.pkeys,
                    self.pkeys,
                    self.pkeys_subset,
                    self.pkeys_overlap,
                    self.pkeys_superset,
                    self.pkeys_proper):
                continue

            if not self._match_context(pk.context):
                continue

            yield pk
