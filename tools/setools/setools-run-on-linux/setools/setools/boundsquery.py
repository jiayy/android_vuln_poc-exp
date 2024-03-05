# Copyright 2016, Tresys Technology, LLC
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
from .policyrep import BoundsRuletype
from .query import PolicyQuery
from .util import match_regex


class BoundsQuery(PolicyQuery):

    """
    Query *bounds statements.

    Parameter:
    policy          The policy to query.

    Keyword Parameters/Class attributes:
    ruletype        The rule type(s) to match.
    """

    ruletype = CriteriaSetDescriptor(enum_class=BoundsRuletype)
    parent = CriteriaDescriptor("parent_regex")
    parent_regex = False
    child = CriteriaDescriptor("child_regex")
    child_regex = False

    def __init__(self, policy, **kwargs):
        super(BoundsQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self):
        """Generator which yields all matching *bounds statements."""
        self.log.info("Generating bounds results from {0.policy}".format(self))
        self.log.debug("Ruletypes: {0.ruletype}".format(self))
        self.log.debug("Parent: {0.parent!r}, regex: {0.parent_regex}".format(self))
        self.log.debug("Child: {0.child!r}, regex: {0.child_regex}".format(self))

        for b in self.policy.bounds():
            if self.ruletype and b.ruletype not in self.ruletype:
                continue

            if self.parent and not match_regex(
                    b.parent,
                    self.parent,
                    self.parent_regex):
                continue

            if self.child and not match_regex(
                    b.child,
                    self.child,
                    self.child_regex):
                continue

            yield b
