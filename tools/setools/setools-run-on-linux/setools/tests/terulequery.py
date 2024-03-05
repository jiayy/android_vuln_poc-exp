"""Type enforcement rule query unit tests."""
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

from setools import TERuleQuery
from setools import TERuletype as TRT

from . import mixins
from .policyrep.util import compile_policy


class TERuleQueryTest(mixins.ValidateRule, unittest.TestCase):

    """Type enforcement rule query unit tests."""

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/terulequery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """TE rule query with no criteria."""
        # query with no parameters gets all TE rules.
        rules = sorted(self.p.terules())

        q = TERuleQuery(self.p)
        q_rules = sorted(q.results())

        self.assertListEqual(rules, q_rules)

    def test_001_source_direct(self):
        """TE rule query with exact, direct, source match."""
        q = TERuleQuery(
            self.p, source="test1a", source_indirect=False, source_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TRT.allow, "test1a", "test1t", "infoflow", set(["hi_w"]))

    def test_002_source_indirect(self):
        """TE rule query with exact, indirect, source match."""
        q = TERuleQuery(
            self.p, source="test2s", source_indirect=True, source_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TRT.allow, "test2a", "test2t", "infoflow", set(["hi_w"]))

    def test_003_source_direct_regex(self):
        """TE rule query with regex, direct, source match."""
        q = TERuleQuery(
            self.p, source="test3a.*", source_indirect=False, source_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TRT.allow, "test3aS", "test3t", "infoflow", set(["low_r"]))

    def test_004_source_indirect_regex(self):
        """TE rule query with regex, indirect, source match."""
        q = TERuleQuery(
            self.p, source="test4(s|t)", source_indirect=True, source_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.allow, "test4a1", "test4a1", "infoflow", set(["hi_w"]))
        self.validate_rule(r[1], TRT.allow, "test4a2", "test4a2", "infoflow", set(["low_r"]))

    def test_005_target_direct(self):
        """TE rule query with exact, direct, target match."""
        q = TERuleQuery(
            self.p, target="test5a", target_indirect=False, target_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TRT.allow, "test5s", "test5a", "infoflow", set(["hi_w"]))

    def test_006_target_indirect(self):
        """TE rule query with exact, indirect, target match."""
        q = TERuleQuery(
            self.p, target="test6t", target_indirect=True, target_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.allow, "test6s", "test6a", "infoflow", set(["hi_w"]))
        self.validate_rule(r[1], TRT.allow, "test6s", "test6t", "infoflow", set(["low_r"]))

    def test_007_target_direct_regex(self):
        """TE rule query with regex, direct, target match."""
        q = TERuleQuery(
            self.p, target="test7a.*", target_indirect=False, target_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TRT.allow, "test7s", "test7aPASS", "infoflow", set(["low_r"]))

    def test_008_target_indirect_regex(self):
        """TE rule query with regex, indirect, target match."""
        q = TERuleQuery(
            self.p, target="test8(s|t)", target_indirect=True, target_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.allow, "test8a1", "test8a1", "infoflow", set(["hi_w"]))
        self.validate_rule(r[1], TRT.allow, "test8a2", "test8a2", "infoflow", set(["low_r"]))

    @unittest.skip("Setting tclass to a string is no longer supported.")
    def test_009_class(self):
        """TE rule query with exact object class match."""
        q = TERuleQuery(self.p, tclass="infoflow2", tclass_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TRT.allow, "test9", "test9", "infoflow2", set(["super_w"]))

    def test_010_class_list(self):
        """TE rule query with object class list match."""
        q = TERuleQuery(
            self.p, tclass=["infoflow3", "infoflow4"], tclass_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.allow, "test10", "test10", "infoflow3", set(["null"]))
        self.validate_rule(r[1], TRT.allow, "test10", "test10", "infoflow4", set(["hi_w"]))

    def test_011_class_regex(self):
        """TE rule query with object class regex match."""
        q = TERuleQuery(self.p, tclass="infoflow(5|6)", tclass_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.allow, "test11", "test11", "infoflow5", set(["low_w"]))
        self.validate_rule(r[1], TRT.allow, "test11", "test11", "infoflow6", set(["med_r"]))

    def test_012_perms_any(self):
        """TE rule query with permission set intersection."""
        q = TERuleQuery(self.p, perms=["super_r"], perms_equal=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.allow, "test12a", "test12a", "infoflow7", set(["super_r"]))
        self.validate_rule(r[1], TRT.allow, "test12b", "test12b", "infoflow7",
                           set(["super_r", "super_none"]))

    def test_013_perms_equal(self):
        """TE rule query with permission set equality."""
        q = TERuleQuery(
            self.p, perms=["super_w", "super_none", "super_both"], perms_equal=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TRT.allow, "test13c", "test13c", "infoflow7",
                           set(["super_w", "super_none", "super_both"]))

    def test_014_ruletype(self):
        """TE rule query with rule type match."""
        q = TERuleQuery(self.p, ruletype=["auditallow", "dontaudit"])

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.auditallow, "test14", "test14", "infoflow7",
                           set(["super_both"]))
        self.validate_rule(r[1], TRT.dontaudit, "test14", "test14", "infoflow7",
                           set(["super_unmapped"]))

    def test_052_perms_subset1(self):
        """TE rule query with permission subset."""
        q = TERuleQuery(self.p, perms=["super_none", "super_both"], perms_subset=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.allow, "test13c", "test13c", "infoflow7",
                           set(["super_w", "super_none", "super_both"]))
        self.validate_rule(r[1], TRT.allow, "test13d", "test13d", "infoflow7",
                           set(["super_w", "super_none", "super_both", "super_unmapped"]))

    def test_052_perms_subset2(self):
        """TE rule query with permission subset (equality)."""
        q = TERuleQuery(self.p, perms=["super_w", "super_none", "super_both", "super_unmapped"],
                        perms_subset=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TRT.allow, "test13d", "test13d", "infoflow7",
                           set(["super_w", "super_none", "super_both", "super_unmapped"]))

    def test_100_default(self):
        """TE rule query with default type exact match."""
        q = TERuleQuery(self.p, default="test100d", default_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TRT.type_transition, "test100", "test100", "infoflow7", "test100d")

    def test_101_default_regex(self):
        """TE rule query with default type regex match."""
        q = TERuleQuery(self.p, default="test101.", default_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.type_transition, "test101", "test101d", "infoflow7",
                           "test101e")
        self.validate_rule(r[1], TRT.type_transition, "test101", "test101e", "infoflow7",
                           "test101d")

    def test_200_boolean_intersection(self):
        """TE rule query with intersection Boolean set match."""
        q = TERuleQuery(self.p, boolean=["test200"])

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.allow, "test200t1", "test200t1", "infoflow7",
                           set(["super_w"]), cond="test200")
        self.validate_rule(r[1], TRT.allow, "test200t2", "test200t2", "infoflow7",
                           set(["super_w"]), cond="test200a && test200")

    def test_201_boolean_equal(self):
        """TE rule query with equal Boolean set match."""
        q = TERuleQuery(self.p, boolean=["test201a", "test201b"], boolean_equal=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TRT.allow, "test201t1", "test201t1", "infoflow7",
                           set(["super_unmapped"]), cond="test201b && test201a")

    def test_202_boolean_regex(self):
        """TE rule query with regex Boolean match."""
        q = TERuleQuery(self.p, boolean="test202(a|b)", boolean_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.allow, "test202t1", "test202t1", "infoflow7",
                           set(["super_none"]), cond="test202a")
        self.validate_rule(r[1], TRT.allow, "test202t2", "test202t2", "infoflow7",
                           set(["super_unmapped"]), cond="test202b || test202c")

    def test_300_issue111(self):
        """TE rule query with attribute source criteria, indirect match."""
        # https://github.com/TresysTechnology/setools/issues/111
        q = TERuleQuery(self.p, source="test300b", source_indirect=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 4)
        self.validate_rule(r[0], TRT.allow, "test300a", "test300target", "infoflow7", set(["hi_w"]))
        self.validate_rule(r[1], TRT.allow, "test300b", "test300target", "infoflow7",
                           set(["super_w"]))
        self.validate_rule(r[2], TRT.allow, "test300t1", "test300t1", "infoflow7", set(["hi_r"]))
        self.validate_rule(r[3], TRT.allow, "test300t2", "test300t2", "infoflow7", set(["med_w"]))

    def test_301_issue111(self):
        """TE rule query with attribute target criteria, indirect match."""
        # https://github.com/TresysTechnology/setools/issues/111
        q = TERuleQuery(self.p, target="test301b", target_indirect=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 4)
        self.validate_rule(r[0], TRT.allow, "test301source", "test301a", "infoflow7", set(["hi_w"]))
        self.validate_rule(r[1], TRT.allow, "test301source", "test301b", "infoflow7",
                           set(["super_w"]))
        self.validate_rule(r[2], TRT.allow, "test301t1", "test301t1", "infoflow7", set(["hi_r"]))
        self.validate_rule(r[3], TRT.allow, "test301t2", "test301t2", "infoflow7", set(["med_w"]))

    def test_302_issue111(self):
        """TE rule query with attribute default type criteria."""
        # https://github.com/TresysTechnology/setools/issues/111
        q = TERuleQuery(self.p, default="test302")

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.type_transition, "test302source", "test302t1", "infoflow7",
                           "test302t1")
        self.validate_rule(r[1], TRT.type_transition, "test302source", "test302t2", "infoflow7",
                           "test302t2")


class TERuleQueryXperm(mixins.ValidateRule, unittest.TestCase):

    """TE Rule Query with extended permission rules."""

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/terulequery2.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_001_source_direct(self):
        """Xperm rule query with exact, direct, source match."""
        q = TERuleQuery(
            self.p, source="test1a", source_indirect=False, source_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TRT.allowxperm, "test1a", "test1t", "infoflow",
                           set(range(0xebe0, 0xebff + 1)), xperm="ioctl")

    def test_002_source_indirect(self):
        """Xperm rule query with exact, indirect, source match."""
        q = TERuleQuery(
            self.p, source="test2s", source_indirect=True, source_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TRT.allowxperm, "test2a", "test2t", "infoflow",
                           set([0x5411, 0x5451]), xperm="ioctl")

    def test_003_source_direct_regex(self):
        """Xperm rule query with regex, direct, source match."""
        q = TERuleQuery(
            self.p, source="test3a.*", source_indirect=False, source_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TRT.allowxperm, "test3aS", "test3t", "infoflow",
                           set([0x1111]), xperm="ioctl")

    def test_004_source_indirect_regex(self):
        """Xperm rule query with regex, indirect, source match."""
        q = TERuleQuery(
            self.p, source="test4(s|t)", source_indirect=True, source_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.allowxperm, "test4a1", "test4a1", "infoflow",
                           set([0x9999]), xperm="ioctl")
        self.validate_rule(r[1], TRT.allowxperm, "test4a2", "test4a2", "infoflow",
                           set([0x1111]), xperm="ioctl")

    def test_005_target_direct(self):
        """Xperm rule query with exact, direct, target match."""
        q = TERuleQuery(
            self.p, target="test5a", target_indirect=False, target_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TRT.allowxperm, "test5s", "test5a", "infoflow", set([0x9999]),
                           xperm="ioctl")

    def test_006_target_indirect(self):
        """Xperm rule query with exact, indirect, target match."""
        q = TERuleQuery(
            self.p, target="test6t", target_indirect=True, target_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.allowxperm, "test6s", "test6a", "infoflow", set([0x9999]),
                           xperm="ioctl")
        self.validate_rule(r[1], TRT.allowxperm, "test6s", "test6t", "infoflow", set([0x1111]),
                           xperm="ioctl")

    def test_007_target_direct_regex(self):
        """Xperm rule query with regex, direct, target match."""
        q = TERuleQuery(
            self.p, target="test7a.*", target_indirect=False, target_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TRT.allowxperm, "test7s", "test7aPASS", "infoflow", set([0x1111]),
                           xperm="ioctl")

    def test_008_target_indirect_regex(self):
        """Xperm rule query with regex, indirect, target match."""
        q = TERuleQuery(
            self.p, target="test8(s|t)", target_indirect=True, target_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.allowxperm, "test8a1", "test8a1", "infoflow", set([0x9999]),
                           xperm="ioctl")
        self.validate_rule(r[1], TRT.allowxperm, "test8a2", "test8a2", "infoflow", set([0x1111]),
                           xperm="ioctl")

    def test_010_class_list(self):
        """Xperm rule query with object class list match."""
        q = TERuleQuery(
            self.p, tclass=["infoflow3", "infoflow4"], tclass_regex=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.allowxperm, "test10", "test10", "infoflow3", set([0]),
                           xperm="ioctl")
        self.validate_rule(r[1], TRT.allowxperm, "test10", "test10", "infoflow4", set([0x9999]),
                           xperm="ioctl")

    def test_011_class_regex(self):
        """Xperm rule query with object class regex match."""
        q = TERuleQuery(self.p, tclass="infoflow(5|6)", tclass_regex=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.allowxperm, "test11", "test11", "infoflow5", set([0x1111]),
                           xperm="ioctl")
        self.validate_rule(r[1], TRT.allowxperm, "test11", "test11", "infoflow6", set([0x5555]),
                           xperm="ioctl")

    def test_014_ruletype(self):
        """Xperm rule query with rule type match."""
        q = TERuleQuery(self.p, ruletype=["auditallowxperm", "dontauditxperm"])

        r = sorted(q.results())
        self.assertEqual(len(r), 2)
        self.validate_rule(r[0], TRT.auditallowxperm, "test14", "test14", "infoflow7",
                           set([0x1234]), xperm="ioctl")
        self.validate_rule(r[1], TRT.dontauditxperm, "test14", "test14", "infoflow7",
                           set([0x4321]), xperm="ioctl")

    def test_100_std_perm_any(self):
        """Xperm rule query match by standard permission."""
        q = TERuleQuery(self.p, ruletype=["neverallow", "neverallowxperm"],
                        perms=set(["ioctl", "hi_w"]), perms_equal=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 0)
        # changed after dropping source policy support
        # self.assertEqual(len(r), 2)
        # self.validate_rule(r[0], TRT.neverallow, "test100", "system", "infoflow2",
        #                   set(["ioctl", "hi_w"]))
        # self.validate_rule(r[1], TRT.neverallowxperm, "test100", "test100", "infoflow2",
        #                   set([0x1234]), xperm="ioctl")

    def test_100_std_perm_equal(self):
        """Xperm rule query match by standard permission, equal perm set."""
        q = TERuleQuery(self.p, ruletype=["neverallow", "neverallowxperm"],
                        perms=set(["ioctl", "hi_w"]), perms_equal=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 0)
        # changed after dropping source policy support
        # self.assertEqual(len(r), 1)
        # self.validate_rule(r[0], TRT.neverallow, "test100", "system", "infoflow2",
        #                   set(["ioctl", "hi_w"]))

    def test_101_xperm_any(self):
        """Xperm rule query match any perm set."""
        q = TERuleQuery(self.p, xperms=[(0x9011, 0x9013)], xperms_equal=False)

        r = sorted(q.results())
        self.assertEqual(len(r), 4)
        self.validate_rule(r[0], TRT.allowxperm, "test101a", "test101a", "infoflow7",
                           set([0x9011]), xperm="ioctl")
        self.validate_rule(r[1], TRT.allowxperm, "test101b", "test101b", "infoflow7",
                           set([0x9011, 0x9012]), xperm="ioctl")
        self.validate_rule(r[2], TRT.allowxperm, "test101c", "test101c", "infoflow7",
                           set([0x9011, 0x9012, 0x9013]), xperm="ioctl")
        self.validate_rule(r[3], TRT.allowxperm, "test101d", "test101d", "infoflow7",
                           set([0x9011, 0x9012, 0x9013, 0x9014]), xperm="ioctl")

    def test_101_xperm_equal(self):
        """Xperm rule query match equal perm set."""
        q = TERuleQuery(self.p, xperms=[(0x9011, 0x9013)], xperms_equal=True)

        r = sorted(q.results())
        self.assertEqual(len(r), 1)
        self.validate_rule(r[0], TRT.allowxperm, "test101c", "test101c", "infoflow7",
                           set([0x9011, 0x9012, 0x9013]), xperm="ioctl")
