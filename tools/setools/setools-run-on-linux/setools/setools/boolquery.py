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

from .descriptors import CriteriaDescriptor
from .mixins import MatchName
from .query import PolicyQuery


class BoolQuery(MatchName, PolicyQuery):

    """Query SELinux policy Booleans.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    name            The Boolean name to match.
    name_regex      If true, regular expression matching
                    will be used on the Boolean name.
    default         The default state to match.  If this
                    is None, the default state not be matched.
    """

    _default = None

    @property
    def default(self):
        return self._default

    @default.setter
    def default(self, value):
        if value is None:
            self._default = None
        else:
            self._default = bool(value)

    def __init__(self, policy, **kwargs):
        super(BoolQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self):
        """Generator which yields all Booleans matching the criteria."""
        self.log.info("Generating Boolean results from {0.policy}".format(self))
        self._match_name_debug(self.log)
        self.log.debug("Default: {0.default}".format(self))

        for boolean in self.policy.bools():
            if not self._match_name(boolean):
                continue

            if self.default is not None and boolean.state != self.default:
                continue

            yield boolean
