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
import re

from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor
from .exception import ConstraintUseError
from .mixins import MatchObjClass, MatchPermission
from .policyrep import ConstraintRuletype
from .query import PolicyQuery
from .util import match_in_set


class ConstraintQuery(MatchObjClass, MatchPermission, PolicyQuery):

    """
    Query constraint rules, (mls)constrain/(mls)validatetrans.

    Parameter:
    policy            The policy to query.

    Keyword Parameters/Class attributes:
    ruletype          The list of rule type(s) to match.
    tclass            The object class(es) to match.
    tclass_regex      If true, use a regular expression for
                      matching the rule's object class.
    perms             The permission(s) to match.
    perms_equal       If true, the permission set of the rule
                      must exactly match the permissions
                      criteria.  If false, any set intersection
                      will match.
    perms_regex       If true, regular expression matching will be used
                      on the permission names instead of set logic.
    role              The name of the role to match in the
                      constraint expression.
    role_indirect     If true, members of an attribute will be
                      matched rather than the attribute itself.
    role_regex        If true, regular expression matching will
                      be used on the role.
    type_             The name of the type/attribute to match in the
                      constraint expression.
    type_indirect     If true, members of an attribute will be
                      matched rather than the attribute itself.
    type_regex        If true, regular expression matching will
                      be used on the type/attribute.
    user              The name of the user to match in the
                      constraint expression.
    user_regex        If true, regular expression matching will
                      be used on the user.
    """

    ruletype = CriteriaSetDescriptor(enum_class=ConstraintRuletype)
    user = CriteriaDescriptor("user_regex", "lookup_user")
    user_regex = False
    role = CriteriaDescriptor("role_regex", "lookup_role")
    role_regex = False
    role_indirect = True
    type_ = CriteriaDescriptor("type_regex", "lookup_type_or_attr")
    type_regex = False
    type_indirect = True

    def __init__(self, policy, **kwargs):
        super(ConstraintQuery, self).__init__(policy, **kwargs)
        self.log = logging.getLogger(__name__)

    def _match_expr(self, expr, criteria, indirect, regex):
        """
        Match roles/types/users in a constraint expression,
        optionally by expanding the contents of attributes.

        Parameters:
        expr        The expression to match.
        criteria    The criteria to match.
        indirect    If attributes in the expression should be expanded.
        regex       If regular expression matching should be used.
        """

        if indirect:
            obj = set()
            for item in expr:
                obj.update(item.expand())
        else:
            obj = expr

        return match_in_set(obj, criteria, regex)

    def results(self):
        """Generator which yields all matching constraints rules."""
        self.log.info("Generating constraint results from {0.policy}".format(self))
        self.log.debug("Ruletypes: {0.ruletype}".format(self))
        self._match_object_class_debug(self.log)
        self._match_perms_debug(self.log)
        self.log.debug("User: {0.user!r}, regex: {0.user_regex}".format(self))
        self.log.debug("Role: {0.role!r}, regex: {0.role_regex}".format(self))
        self.log.debug("Type: {0.type_!r}, regex: {0.type_regex}".format(self))

        for c in self.policy.constraints():
            if self.ruletype:
                if c.ruletype not in self.ruletype:
                    continue

            if not self._match_object_class(c):
                continue

            try:
                if not self._match_perms(c):
                    continue
            except ConstraintUseError:
                continue

            if self.role and not self._match_expr(
                    c.expression.roles,
                    self.role,
                    self.role_indirect,
                    self.role_regex):
                continue

            if self.type_ and not self._match_expr(
                    c.expression.types,
                    self.type_,
                    self.type_indirect,
                    self.type_regex):
                continue

            if self.user and not self._match_expr(
                    c.expression.users,
                    self.user,
                    False,
                    self.user_regex):
                continue

            yield c
