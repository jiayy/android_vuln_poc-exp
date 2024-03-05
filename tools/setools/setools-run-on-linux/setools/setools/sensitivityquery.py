# Copyright 2015, Tresys Technology, LLC
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
from .mixins import MatchAlias, MatchName
from .query import PolicyQuery
from .util import match_level


class SensitivityQuery(MatchAlias, MatchName, PolicyQuery):

    """
    Query MLS Sensitivities

    Parameter:
    policy       The policy to query.

    Keyword Parameters/Class attributes:
    name         The name of the category to match.
    name_regex   If true, regular expression matching will
                 be used for matching the name.
    alias        The alias name to match.
    alias_regex  If true, regular expression matching
                 will be used on the alias names.
    sens         The criteria to match the sensitivity by dominance.
    sens_dom     If true, the criteria will match if it dominates
                 the sensitivity.
    sens_domby   If true, the criteria will match if it is dominated
                 by the sensitivity.
    """

    sens = CriteriaDescriptor(lookup_function="lookup_sensitivity")
    sens_dom = False
    sens_domby = False

    def __init__(self, policy, **kwargs):
        super(SensitivityQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self):
        """Generator which yields all matching sensitivities."""
        self.log.info("Generating sensitivity results from {0.policy}".format(self))
        self._match_name_debug(self.log)
        self._match_alias_debug(self.log)
        self.log.debug("Sens: {0.sens!r}, dom: {0.sens_dom}, domby: {0.sens_domby}".format(self))

        for s in self.policy.sensitivities():
            if not self._match_name(s):
                continue

            if not self._match_alias(s):
                continue

            if self.sens and not match_level(
                    s,
                    self.sens,
                    self.sens_dom,
                    self.sens_domby,
                    False):
                continue

            yield s
