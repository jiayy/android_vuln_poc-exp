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
# pylint: disable=undefined-variable,no-member
import unittest
from unittest.mock import Mock

from setools import SELinuxPolicy
from setools.exception import InvalidCommon, InvalidClass


@unittest.skip("Needs to be reworked for cython")
class CommonTest(unittest.TestCase):

    @staticmethod
    def mock_common(name, perms):
        policy = Mock(qpol.qpol_policy_t)
        com = Mock(qpol.qpol_common_t)
        com.name.return_value = name
        com.perm_iter = lambda x: iter(perms)
        return common_factory(policy, com)

    @classmethod
    def setUpClass(cls):
        cls.p = SELinuxPolicy("tests/policyrep/objclass.conf")

    def test_001_lookup(self):
        """Common: factory policy lookup."""
        com = common_factory(self.p.policy, "com_a")
        self.assertEqual("com_a", com.qpol_symbol.name(self.p.policy))

    def test_002_lookup_invalid(self):
        """Common: factory policy invalid lookup."""
        with self.assertRaises(InvalidCommon):
            common_factory(self.p.policy, "INVALID")

    def test_003_lookup_object(self):
        """Common: factory policy lookup of Common object."""
        com1 = common_factory(self.p.policy, "com_b")
        com2 = common_factory(self.p.policy, com1)
        self.assertIs(com2, com1)

    def test_010_string(self):
        """Common: string representation"""
        com = self.mock_common("test10", ["perm1", "perm2"])
        self.assertEqual("test10", str(com))

    def test_020_perms(self):
        """Common: permissions"""
        com = self.mock_common("test20", ["perm1", "perm2"])
        self.assertEqual(set(["perm1", "perm2"]), com.perms)

    def test_030_statment(self):
        """Common: statement."""
        com = self.mock_common("test30", ["perm1", "perm2"])
        self.assertRegex(com.statement(), "("
                         "common test30\n{\n\tperm1\n\tperm2\n}"
                         "|"
                         "common test30\n{\n\tperm2\n\tperm1\n}"
                         ")")

    def test_040_contains(self):
        """Common: contains"""
        com = self.mock_common("test40", ["perm1", "perm2"])
        self.assertIn("perm1", com)
        self.assertNotIn("perm3", com)


@unittest.skip("Needs to be reworked for cython")
class ObjClassTest(unittest.TestCase):

    @staticmethod
    def mock_class(name, perms, com_perms=[]):
        policy = Mock(qpol.qpol_policy_t)

        cls = Mock(qpol.qpol_class_t)
        cls.name.return_value = name
        cls.perm_iter = lambda x: iter(perms)

        if com_perms:
            com = Mock(qpol.qpol_common_t)
            com.name.return_value = name + "_common"
            com.perm_iter = lambda x: iter(com_perms)
            cls.common.return_value = com
        else:
            cls.common.side_effect = ValueError

        return class_factory(policy, cls)

    @classmethod
    def setUpClass(cls):
        cls.p = SELinuxPolicy("tests/policyrep/objclass.conf")

    def test_001_lookup(self):
        """ObjClass: factory policy lookup."""
        cls = class_factory(self.p.policy, "infoflow")
        self.assertEqual("infoflow", cls.qpol_symbol.name(self.p.policy))

    def test_002_lookup_invalid(self):
        """ObjClass: factory policy invalid lookup."""
        with self.assertRaises(InvalidClass):
            class_factory(self.p.policy, "INVALID")

    def test_003_lookup_object(self):
        """ObjClass: factory policy lookup of ObjClass object."""
        cls1 = class_factory(self.p.policy, "infoflow4")
        cls2 = class_factory(self.p.policy, cls1)
        self.assertIs(cls2, cls1)

    def test_010_string(self):
        """ObjClass: string representation"""
        cls = self.mock_class("test10", ["perm1", "perm2"])
        self.assertEqual("test10", str(cls))

    def test_020_perms(self):
        """ObjClass: permissions"""
        cls = self.mock_class("test20", ["perm1", "perm2"], com_perms=["perm3", "perm4"])
        self.assertEqual(set(["perm1", "perm2"]), cls.perms)

    def test_030_statment(self):
        """ObjClass: statement, no common."""
        cls = self.mock_class("test30", ["perm1", "perm2"])
        self.assertRegex(cls.statement(), "("
                         "class test30\n{\n\tperm1\n\tperm2\n}"
                         "|"
                         "class test30\n{\n\tperm2\n\tperm1\n}"
                         ")")

    def test_031_statment(self):
        """ObjClass: statement, with common."""
        cls = self.mock_class("test31", ["perm1", "perm2"], com_perms=["perm3", "perm4"])
        self.assertRegex(cls.statement(), "("
                         "class test31\ninherits test31_common\n{\n\tperm1\n\tperm2\n}"
                         "|"
                         "class test31\ninherits test31_common\n{\n\tperm2\n\tperm1\n}"
                         ")")

    def test_032_statment(self):
        """ObjClass: statement, with common, no class perms."""
        cls = self.mock_class("test32", [], com_perms=["perm3", "perm4"])
        self.assertRegex(cls.statement(), "("
                         "class test32\ninherits test32_common"
                         "|"
                         "class test32\ninherits test32_common"
                         ")")

    def test_040_contains(self):
        """ObjClass: contains"""
        cls = self.mock_class("test40", ["perm1", "perm2"])
        self.assertIn("perm1", cls)
        self.assertNotIn("perm3", cls)

    def test_041_contains_common(self):
        """ObjClass: contains, with common"""
        cls = self.mock_class("test41", ["perm1", "perm2"], com_perms=["perm3", "perm4"])
        self.assertIn("perm1", cls)
        self.assertIn("perm3", cls)
        self.assertNotIn("perm5", cls)
