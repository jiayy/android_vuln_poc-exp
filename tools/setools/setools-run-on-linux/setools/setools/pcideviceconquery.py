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
from .query import PolicyQuery


class PcideviceconQuery(MatchContext, PolicyQuery):

    """
    Pcidevicecon context query.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    device          A single PCI device ID.

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

    _device = None

    @property
    def device(self):
        return self._device

    @device.setter
    def device(self, value):
        if value:
            if value < 1:
                raise ValueError("PCI device ID must be positive: {0}".format(value))

            self._device = value
        else:
            self._device = None

    def __init__(self, policy, **kwargs):
        super(PcideviceconQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self):
        """Generator which yields all matching pcidevicecons."""
        self.log.info("Generating results from {0.policy}".format(self))
        self.log.debug("Device ID: {0.device!r}".format(self))
        self._match_context_debug(self.log)

        for pcidevicecon in self.policy.pcidevicecons():

            if self.device and self.device != pcidevicecon.device:
                continue

            if not self._match_context(pcidevicecon.context):
                continue

            yield pcidevicecon
