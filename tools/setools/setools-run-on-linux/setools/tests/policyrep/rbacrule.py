# Copyright 2015, Tresys Technology, LLC
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with SETools.  If not, see <http://www.gnu.org/licenses/>.
#
# Until this is fixed for cython:
# pylint: disable=undefined-variable
import unittest
from unittest.mock import Mock, patch

from setools.exception import InvalidRBACRuleType, RuleNotConditional, RuleUseError


@unittest.skip("Needs to be reworked for cython")
@patch('setools.policyrep.role.role_factory', lambda x, y: y)
class RoleAllowTest(unittest.TestCase):

    def mock_avrule_factory(self, source, target):
        mock_rule = Mock(qpol_role_allow_t)
        mock_rule.rule_type.return_value = RBACRuletype.allow
        mock_rule.source_role.return_value = source
        mock_rule.target_role.return_value = target

        return rbac_rule_factory(self.p, mock_rule)

    def setUp(self):
        self.p = Mock(qpol_policy_t)

    def test_000_factory(self):
        """RoleAllow factory lookup."""
        with self.assertRaises(TypeError):
            rbac_rule_factory(self.p, "INVALID")

    @unittest.skip("RBAC ruletype changed to an enumeration.")
    def test_001_validate_ruletype(self):
        """RoleAllow valid rule types."""
        # no return value means a return of None
        self.assertEqual("allow", validate_ruletype("allow"))

    def test_002_validate_ruletype_invalid(self):
        """RoleAllow valid rule types."""
        with self.assertRaises(InvalidRBACRuleType):
            self.assertTrue(validate_ruletype("range_transition"))

    def test_010_ruletype(self):
        """RoleAllow rule type"""
        rule = self.mock_avrule_factory("a", "b")
        self.assertEqual(RBACRuletype.allow, rule.ruletype)

    def test_020_source_role(self):
        """RoleAllow source role"""
        rule = self.mock_avrule_factory("source20", "b")
        self.assertEqual("source20", rule.source)

    def test_030_target_role(self):
        """RoleAllow target role"""
        rule = self.mock_avrule_factory("a", "target30")
        self.assertEqual("target30", rule.target)

    def test_040_object_class(self):
        """RoleAllow object class"""
        rule = self.mock_avrule_factory("a", "b")
        with self.assertRaises(RuleUseError):
            rule.tclass

    def test_060_conditional(self):
        """RoleAllow conditional expression"""
        rule = self.mock_avrule_factory("a", "b")
        with self.assertRaises(RuleNotConditional):
            rule.conditional

    def test_070_default(self):
        """RoleAllow default role"""
        rule = self.mock_avrule_factory("a", "b")
        with self.assertRaises(RuleUseError):
            rule.default

    def test_100_statement_one_perm(self):
        """RoleAllow statement."""
        rule = self.mock_avrule_factory("a", "b")
        self.assertEqual("allow a b;", rule.statement())


@unittest.skip("Needs to be reworked for cython")
@patch('setools.policyrep.role.role_factory', lambda x, y: y)
@patch('setools.policyrep.typeattr.type_or_attr_factory', lambda x, y: y)
@patch('setools.policyrep.objclass.class_factory', lambda x, y: y)
class RoleTransitionTest(unittest.TestCase):

    def mock_roletrans_factory(self, source, target, tclass, default):
        mock_rule = Mock(qpol_role_trans_t)
        mock_rule.rule_type.return_value = RBACRuletype.role_transition
        mock_rule.source_role.return_value = source
        mock_rule.target_type.return_value = target
        mock_rule.object_class.return_value = tclass
        mock_rule.default_role.return_value = default

        return rbac_rule_factory(self.p, mock_rule)

    def setUp(self):
        self.p = Mock(qpol_policy_t)

    def test_000_factory(self):
        """RoleTransition factory lookup."""
        with self.assertRaises(TypeError):
            rbac_rule_factory(self.p, "INVALID")

    def test_001_validate_ruletype(self):
        """RoleTransition valid rule types."""
        self.assertEqual(RBACRuletype.role_transition, validate_ruletype("role_transition"))

    def test_002_validate_ruletype_invalid(self):
        """RoleTransition valid rule types."""
        with self.assertRaises(InvalidRBACRuleType):
            self.assertTrue(validate_ruletype("type_transition"))

    def test_010_ruletype(self):
        """RoleTransition rule type"""
        rule = self.mock_roletrans_factory("a", "b", "c", "d")
        self.assertEqual(RBACRuletype.role_transition, rule.ruletype)

    def test_020_source_role(self):
        """RoleTransition source role"""
        rule = self.mock_roletrans_factory("source20", "b", "c", "d")
        self.assertEqual("source20", rule.source)

    def test_030_target_type(self):
        """RoleTransition target type"""
        rule = self.mock_roletrans_factory("a", "target30", "c", "d")
        self.assertEqual("target30", rule.target)

    def test_040_object_class(self):
        """RoleTransition object class"""
        rule = self.mock_roletrans_factory("a", "b", "class40", "d")
        self.assertEqual("class40", rule.tclass)

    def test_050_default(self):
        """RoleTransition default role"""
        rule = self.mock_roletrans_factory("a", "b", "c", "default50")
        self.assertEqual("default50", rule.default)

    def test_060_conditional(self):
        """RoleTransition conditional expression"""
        rule = self.mock_roletrans_factory("a", "b", "c", "d")
        with self.assertRaises(RuleNotConditional):
            rule.conditional

    def test_100_statement(self):
        """RoleTransition statement."""
        rule = self.mock_roletrans_factory("a", "b", "c", "d")
        self.assertEqual("role_transition a b:c d;", rule.statement())
