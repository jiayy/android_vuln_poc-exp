"""RBAC rule query unit tests."""
# Copyright 2014, Tresys Technology, LLC
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
# pylint: disable=invalid-name,too-many-public-methods
import os
import unittest

from setools import RBACRuleQuery
from setools import RBACRuletype as RRT
from setools.exception import RuleUseError, RuleNotConditional

from . import mixins
from .policyrep.util import compile_policy


class RBACRuleQueryTest(mixins.ValidateRule, unittest.TestCase):

    """RBAC rule query unit tests."""

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/rbacrulequery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def validate_allow(self, rule, source, target):
        """Validate a role allow rule."""
        self.assertEqual(RRT.allow, rule.ruletype)
        self.assertEqual(source, rule.source)
        self.assertEqual(target, rule.target)
        self.assertRaises(RuleUseError, getattr, rule, "tclass")
        self.assertRaises(RuleUseError, getattr, rule, "default")
        self.assertRaises(RuleNotConditional, getattr, rule, "conditional")

    def test_000_unset(self):
        """RBAC rule query with no criteria."""
        # query with no parameters gets all RBAC rules.
        rules = sorted(self.p.rbacrules())

        q = RBACRuleQuery(self.p)
        q_rules = sorted(q.results())

        self.assertListEqual(rules, q_rules)

    def test_001_source_direct(self):
        """RBAC rule query with exact, direct, source match."""
        q = RBACRuleQuery(
            self.p, source="test1s", source_indirect=False, source_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)

        self.validate_allow(r[0], "test1s", "test1t")
        self.validate_rule(r[1], RRT.role_transition, "test1s", "system", "infoflow", "test1t")

    def test_002_source_direct_regex(self):
        """RBAC rule query with regex, direct, source match."""
        q = RBACRuleQuery(
            self.p, source="test2s(1|2)", source_indirect=False, source_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_allow(r[0], "test2s1", "test2t")

    def test_010_target_direct(self):
        """RBAC rule query with exact, direct, target match."""
        q = RBACRuleQuery(
            self.p, target="test10t", target_indirect=False, target_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_allow(r[0], "test10s", "test10t")

    def test_011_target_direct_regex(self):
        """RBAC rule query with regex, direct, target match."""
        q = RBACRuleQuery(
            self.p, target="test11t(1|3)", target_indirect=False, target_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_allow(r[0], "test11s", "test11t1")

    def test_012_target_type(self):
        """RBAC rule query with a type as target."""
        q = RBACRuleQuery(self.p, target="test12t")

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RRT.role_transition, "test12s", "test12t", "infoflow", "test12d")

    @unittest.skip("Setting tclass to a string is no longer supported.")
    def test_020_class(self):
        """RBAC rule query with exact object class match."""
        q = RBACRuleQuery(self.p, tclass="infoflow2", tclass_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RRT.role_transition, "test20", "system", "infoflow2", "test20d2")

    def test_021_class_list(self):
        """RBAC rule query with object class list match."""
        q = RBACRuleQuery(
            self.p, tclass=["infoflow3", "infoflow4"], tclass_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], RRT.role_transition, "test21", "system", "infoflow3", "test21d3")
        self.validate_rule(r[1], RRT.role_transition, "test21", "system", "infoflow4", "test21d2")

    def test_022_class_regex(self):
        """RBAC rule query with object class regex match."""
        q = RBACRuleQuery(self.p, tclass="infoflow(5|6)", tclass_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], RRT.role_transition, "test22", "system", "infoflow5", "test22d2")
        self.validate_rule(r[1], RRT.role_transition, "test22", "system", "infoflow6", "test22d3")

    def test_030_default(self):
        """RBAC rule query with exact default match."""
        q = RBACRuleQuery(
            self.p, default="test30d", default_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RRT.role_transition, "test30s", "system", "infoflow", "test30d")

    def test_031_default_regex(self):
        """RBAC rule query with regex default match."""
        q = RBACRuleQuery(
            self.p, default="test31d(2|3)", default_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], RRT.role_transition, "test31s", "system", "infoflow7", "test31d3")
        self.validate_rule(r[1], RRT.role_transition, "test31s", "system", "process", "test31d2")

    def test_040_ruletype(self):
        """RBAC rule query with rule type."""
        q = RBACRuleQuery(self.p, ruletype=[RRT.allow])

        num = 0
        for num, r in enumerate(sorted(q.results()), start=1):
            self.assertEqual(r.ruletype, RRT.allow)

        # this will have to be updated as number of
        # role allows change in the test policy
        self.assertEqual(num, 9)
