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
from socket import IPPROTO_TCP, IPPROTO_UDP

from .mixins import MatchContext
from .query import PolicyQuery
from .policyrep import PortconRange, PortconProtocol
from .util import match_range


class PortconQuery(MatchContext, PolicyQuery):

    """
    Port context query.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    protocol        The protocol to match (socket.IPPROTO_TCP for
                    TCP or socket.IPPROTO_UDP for UDP)

    ports           A 2-tuple of the port range to match. (Set both to
                    the same value for a single port)
    ports_subset    If true, the criteria will match if it is a subset
                    of the portcon's range.
    ports_overlap   If true, the criteria will match if it overlaps
                    any of the portcon's range.
    ports_superset  If true, the criteria will match if it is a superset
                    of the portcon's range.
    ports_proper    If true, use proper superset/subset operations.
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

    _protocol = None
    _ports = None
    ports_subset = False
    ports_overlap = False
    ports_superset = False
    ports_proper = False

    @property
    def ports(self):
        return self._ports

    @ports.setter
    def ports(self, value):
        pending_ports = PortconRange(*value)

        if all(pending_ports):
            if pending_ports.low < 1 or pending_ports.high < 1:
                raise ValueError("Port numbers must be positive: {0.low}-{0.high}".
                                 format(pending_ports))

            if pending_ports.low > pending_ports.high:
                raise ValueError(
                    "The low port must be smaller than the high port: {0.low}-{0.high}".
                    format(pending_ports))

            self._ports = pending_ports
        else:
            self._ports = None

    @property
    def protocol(self):
        return self._protocol

    @protocol.setter
    def protocol(self, value):
        if value:
            self._protocol = PortconProtocol.lookup(value)
        else:
            self._protocol = None

    def __init__(self, policy, **kwargs):
        super(PortconQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self):
        """Generator which yields all matching portcons."""
        self.log.info("Generating portcon results from {0.policy}".format(self))
        self.log.debug("Ports: {0.ports}, overlap: {0.ports_overlap}, "
                       "subset: {0.ports_subset}, superset: {0.ports_superset}, "
                       "proper: {0.ports_proper}".format(self))
        self.log.debug("Protocol: {0.protocol!r}".format(self))
        self._match_context_debug(self.log)

        for portcon in self.policy.portcons():

            if self.ports and not match_range(
                    portcon.ports,
                    self.ports,
                    self.ports_subset,
                    self.ports_overlap,
                    self.ports_superset,
                    self.ports_proper):
                continue

            if self.protocol and self.protocol != portcon.protocol:
                continue

            if not self._match_context(portcon.context):
                continue

            yield portcon
