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

from .query import PolicyQuery
from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor
from .mixins import MatchObjClass
from .policyrep import DefaultRuletype, DefaultValue, DefaultRangeValue


class DefaultQuery(MatchObjClass, PolicyQuery):

    """
    Query default_* statements.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    ruletype        The rule type(s) to match.
    tclass          The object class(es) to match.
    tclass_regex    If true, use a regular expression for
                    matching the rule's object class.
    default         The default to base new contexts (e.g. "source" or "target")
    default_range   The range to use on new context, default_range only
                    ("low", "high", "low_high")
    """

    ruletype = CriteriaSetDescriptor(enum_class=DefaultRuletype)
    default = CriteriaDescriptor(enum_class=DefaultValue)
    default_range = CriteriaDescriptor(enum_class=DefaultRangeValue)

    def __init__(self, policy, **kwargs):
        super(DefaultQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self):
        """Generator which yields all matching default_* statements."""
        self.log.info("Generating default_* results from {0.policy}".format(self))
        self.log.debug("Ruletypes: {0.ruletype!r}".format(self))
        self._match_object_class_debug(self.log)
        self.log.debug("Default: {0.default!r}".format(self))
        self.log.debug("Range: {0.default_range!r}".format(self))

        for d in self.policy.defaults():
            if self.ruletype and d.ruletype not in self.ruletype:
                continue

            if not self._match_object_class(d):
                continue

            if self.default and d.default != self.default:
                continue

            if self.default_range:
                try:
                    if d.default_range != self.default_range:
                        continue
                except AttributeError:
                    continue

            yield d
