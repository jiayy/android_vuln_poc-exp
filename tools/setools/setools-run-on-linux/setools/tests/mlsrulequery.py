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
import os
import unittest

from setools import MLSRuleQuery
from setools import MLSRuletype as RT

from . import mixins
from .policyrep.util import compile_policy

# Note: the test policy has been written assuming range_transition
# statements could have attributes.  However, range_transition
# statements are always expanded, so the below unit tests
# have been adjusted to this fact (hence a "FAIL" in one of the
# expected type names)


class MLSRuleQueryTest(mixins.ValidateRule, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/mlsrulequery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """MLS rule query with no criteria."""
        # query with no parameters gets all MLS rules.
        rules = sorted(self.p.mlsrules())

        q = MLSRuleQuery(self.p)
        q_rules = sorted(q.results())

        self.assertListEqual(rules, q_rules)

    def test_001_source_direct(self):
        """MLS rule query with exact, direct, source match."""
        q = MLSRuleQuery(
            self.p, source="test1s", source_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test1s", "test1t", "infoflow", "s0")

    def test_003_source_direct_regex(self):
        """MLS rule query with regex, direct, source match."""
        q = MLSRuleQuery(
            self.p, source="test3(s|aS)", source_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], RT.range_transition, "test3s", "test3t", "infoflow", "s1")
        self.validate_rule(r[1], RT.range_transition, "test3s", "test3t", "infoflow2", "s2")

    def test_005_issue111(self):
        """MLS rule query with attribute source criteria, indirect match."""
        # https://github.com/TresysTechnology/setools/issues/111
        q = MLSRuleQuery(self.p, source="test5b", source_indirect=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], RT.range_transition, "test5t1", "test5target", "infoflow", "s1")
        self.validate_rule(r[1], RT.range_transition, "test5t2", "test5target", "infoflow7", "s2")

    def test_010_target_direct(self):
        """MLS rule query with exact, direct, target match."""
        q = MLSRuleQuery(
            self.p, target="test10t", target_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], RT.range_transition, "test10s", "test10t", "infoflow", "s0")
        self.validate_rule(r[1], RT.range_transition, "test10s", "test10t", "infoflow2", "s1")

    def test_012_target_direct_regex(self):
        """MLS rule query with regex, direct, target match."""
        q = MLSRuleQuery(
            self.p, target="test12a.*", target_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test12s", "test12aFAIL", "infoflow", "s2")

    def test_014_issue111(self):
        """MLS rule query with attribute target criteria, indirect match."""
        # https://github.com/TresysTechnology/setools/issues/111
        q = MLSRuleQuery(self.p, target="test14b", target_indirect=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], RT.range_transition, "test14source", "test14t1", "infoflow", "s1")
        self.validate_rule(r[1], RT.range_transition, "test14source", "test14t2", "infoflow7", "s2")

    @unittest.skip("Setting tclass to a string is no longer supported.")
    def test_020_class(self):
        """MLS rule query with exact object class match."""
        q = MLSRuleQuery(self.p, tclass="infoflow7", tclass_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test20", "test20", "infoflow7", "s1")

    def test_021_class_list(self):
        """MLS rule query with object class list match."""
        q = MLSRuleQuery(
            self.p, tclass=["infoflow3", "infoflow4"], tclass_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], RT.range_transition, "test21", "test21", "infoflow3", "s2")
        self.validate_rule(r[1], RT.range_transition, "test21", "test21", "infoflow4", "s1")

    def test_022_class_regex(self):
        """MLS rule query with object class regex match."""
        q = MLSRuleQuery(self.p, tclass="infoflow(5|6)", tclass_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], RT.range_transition, "test22", "test22", "infoflow5", "s1")
        self.validate_rule(r[1], RT.range_transition, "test22", "test22", "infoflow6", "s2")

    def test_040_range_exact(self):
        """MLS rule query with context range exact match"""
        q = MLSRuleQuery(self.p, default="s40:c1 - s40:c0.c4")

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test40", "test40", "infoflow",
                           "s40:c1 - s40:c0.c4")

    def test_041_range_overlap1(self):
        """MLS rule query with context range overlap match (equal)"""
        q = MLSRuleQuery(self.p, default="s41:c1 - s41:c0.c4", default_overlap=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test41", "test41", "infoflow",
                           "s41:c1 - s41:c1.c3")

    def test_041_range_overlap2(self):
        """MLS rule query with context range overlap match (subset)"""
        q = MLSRuleQuery(self.p, default="s41:c1,c2 - s41:c0.c3", default_overlap=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test41", "test41", "infoflow",
                           "s41:c1 - s41:c1.c3")

    def test_041_range_overlap3(self):
        """MLS rule query with context range overlap match (superset)"""
        q = MLSRuleQuery(self.p, default="s41 - s41:c0.c4", default_overlap=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test41", "test41", "infoflow",
                           "s41:c1 - s41:c1.c3")

    def test_041_range_overlap4(self):
        """MLS rule query with context range overlap match (overlap low level)"""
        q = MLSRuleQuery(self.p, default="s41 - s41:c1,c2", default_overlap=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test41", "test41", "infoflow",
                           "s41:c1 - s41:c1.c3")

    def test_041_range_overlap5(self):
        """MLS rule query with context range overlap match (overlap high level)"""
        q = MLSRuleQuery(self.p, default="s41:c1,c2 - s41:c0.c4", default_overlap=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test41", "test41", "infoflow",
                           "s41:c1 - s41:c1.c3")

    def test_042_range_subset1(self):
        """MLS rule query with context range subset match"""
        q = MLSRuleQuery(self.p, default="s42:c1,c2 - s42:c0.c3", default_overlap=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test42", "test42", "infoflow",
                           "s42:c1 - s42:c1.c3")

    def test_042_range_subset2(self):
        """MLS rule query with context range subset match (equal)"""
        q = MLSRuleQuery(self.p, default="s42:c1 - s42:c1.c3", default_overlap=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test42", "test42", "infoflow",
                           "s42:c1 - s42:c1.c3")

    def test_043_range_superset1(self):
        """MLS rule query with context range superset match"""
        q = MLSRuleQuery(self.p, default="s43 - s43:c0.c4", default_superset=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test43", "test43", "infoflow",
                           "s43:c1 - s43:c1.c3")

    def test_043_range_superset2(self):
        """MLS rule query with context range superset match (equal)"""
        q = MLSRuleQuery(self.p, default="s43:c1 - s43:c1.c3", default_superset=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test43", "test43", "infoflow",
                           "s43:c1 - s43:c1.c3")

    def test_044_range_proper_subset1(self):
        """MLS rule query with context range proper subset match"""
        q = MLSRuleQuery(self.p, default="s44:c1,c2", default_subset=True, default_proper=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test44", "test44", "infoflow",
                           "s44:c1 - s44:c1.c3")

    def test_044_range_proper_subset2(self):
        """MLS rule query with context range proper subset match (equal)"""
        q = MLSRuleQuery(self.p,
                         default="s44:c1 - s44:c1.c3", default_subset=True, default_proper=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 0)

    def test_044_range_proper_subset3(self):
        """MLS rule query with context range proper subset match (equal low only)"""
        q = MLSRuleQuery(self.p,
                         default="s44:c1 - s44:c1.c2", default_subset=True, default_proper=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test44", "test44", "infoflow",
                           "s44:c1 - s44:c1.c3")

    def test_044_range_proper_subset4(self):
        """MLS rule query with context range proper subset match (equal high only)"""
        q = MLSRuleQuery(self.p,
                         default="s44:c1,c2 - s44:c1.c3", default_subset=True, default_proper=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test44", "test44", "infoflow",
                           "s44:c1 - s44:c1.c3")

    def test_045_range_proper_superset1(self):
        """MLS rule query with context range proper superset match"""
        q = MLSRuleQuery(self.p,
                         default="s45 - s45:c0.c4", default_superset=True, default_proper=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test45", "test45", "infoflow",
                           "s45:c1 - s45:c1.c3")

    def test_045_range_proper_superset2(self):
        """MLS rule query with context range proper superset match (equal)"""
        q = MLSRuleQuery(self.p,
                         default="s45:c1 - s45:c1.c3", default_superset=True, default_proper=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 0)

    def test_045_range_proper_superset3(self):
        """MLS rule query with context range proper superset match (equal low)"""
        q = MLSRuleQuery(self.p,
                         default="s45:c1 - s45:c1.c4", default_superset=True, default_proper=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test45", "test45", "infoflow",
                           "s45:c1 - s45:c1.c3")

    def test_045_range_proper_superset4(self):
        """MLS rule query with context range proper superset match (equal high)"""
        q = MLSRuleQuery(self.p,
                         default="s45 - s45:c1.c3", default_superset=True, default_proper=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], RT.range_transition, "test45", "test45", "infoflow",
                           "s45:c1 - s45:c1.c3")

    def test_900_invalid_ruletype(self):
        """MLS rule query with invalid rule type."""
        with self.assertRaises(KeyError):
            q = MLSRuleQuery(self.p, ruletype=["type_transition"])
