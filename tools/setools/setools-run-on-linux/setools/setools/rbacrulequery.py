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

from . import mixins, query
from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor
from .exception import InvalidType, RuleUseError
from .policyrep import RBACRuletype
from .util import match_indirect_regex


class RBACRuleQuery(mixins.MatchObjClass, query.PolicyQuery):

    """
    Query the RBAC rules.

    Parameter:
    policy            The policy to query.

    Keyword Parameters/Class attributes:
    ruletype        The list of rule type(s) to match.
    source          The name of the source role/attribute to match.
    source_indirect If true, members of an attribute will be
                    matched rather than the attribute itself.
    source_regex    If true, regular expression matching will
                    be used on the source role/attribute.
                    Obeys the source_indirect option.
    target          The name of the target role/attribute to match.
    target_indirect If true, members of an attribute will be
                    matched rather than the attribute itself.
    target_regex    If true, regular expression matching will
                    be used on the target role/attribute.
                    Obeys target_indirect option.
    tclass          The object class(es) to match.
    tclass_regex    If true, use a regular expression for
                    matching the rule's object class.
    default         The name of the default role to match.
    default_regex   If true, regular expression matching will
                    be used on the default role.
    """

    ruletype = CriteriaSetDescriptor(enum_class=RBACRuletype)
    source = CriteriaDescriptor("source_regex", "lookup_role")
    source_regex = False
    source_indirect = True
    _target = None
    target_regex = False
    target_indirect = True
    tclass = CriteriaSetDescriptor("tclass_regex", "lookup_class")
    tclass_regex = False
    default = CriteriaDescriptor("default_regex", "lookup_role")
    default_regex = False

    @property
    def target(self):
        return self._target

    @target.setter
    def target(self, value):
        if not value:
            self._target = None
        elif self.target_regex:
            self._target = re.compile(value)
        else:
            try:
                self._target = self.policy.lookup_type_or_attr(value)
            except InvalidType:
                self._target = self.policy.lookup_role(value)

    def __init__(self, policy, **kwargs):
        super(RBACRuleQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def results(self):
        """Generator which yields all matching RBAC rules."""
        self.log.info("Generating RBAC rule results from {0.policy}".format(self))
        self.log.debug("Ruletypes: {0.ruletype}".format(self))
        self.log.debug("Source: {0.source!r}, indirect: {0.source_indirect}, "
                       "regex: {0.source_regex}".format(self))
        self.log.debug("Target: {0.target!r}, indirect: {0.target_indirect}, "
                       "regex: {0.target_regex}".format(self))
        self._match_object_class_debug(self.log)
        self.log.debug("Default: {0.default!r}, regex: {0.default_regex}".format(self))

        for rule in self.policy.rbacrules():
            #
            # Matching on rule type
            #
            if self.ruletype:
                if rule.ruletype not in self.ruletype:
                    continue

            #
            # Matching on source role
            #
            if self.source and not match_indirect_regex(
                    rule.source,
                    self.source,
                    self.source_indirect,
                    self.source_regex):
                continue

            #
            # Matching on target type (role_transition)/role(allow)
            #
            if self.target and not match_indirect_regex(
                    rule.target,
                    self.target,
                    self.target_indirect,
                    self.target_regex):
                continue

            #
            # Matching on object class
            #
            try:
                if not self._match_object_class(rule):
                    continue
            except RuleUseError:
                continue

            #
            # Matching on default role
            #
            if self.default:
                try:
                    # because default role is always a single
                    # role, hard-code indirect to True
                    # so the criteria can be an attribute
                    if not match_indirect_regex(
                            rule.default,
                            self.default,
                            True,
                            self.default_regex):
                        continue
                except RuleUseError:
                    continue

            # if we get here, we have matched all available criteria
            yield rule
