# Copyright 2014-2015, Tresys Technology, LLC
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

from setools import UserQuery

from .policyrep.util import compile_policy


class UserQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/userquery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """User query with no criteria."""
        # query with no parameters gets all types.
        allusers = sorted(self.p.users())

        q = UserQuery(self.p)
        qusers = sorted(q.results())

        self.assertListEqual(allusers, qusers)

    def test_001_name_exact(self):
        """User query with exact name match."""
        q = UserQuery(self.p, name="test1_u")

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test1_u"], users)

    def test_002_name_regex(self):
        """User query with regex name match."""
        q = UserQuery(self.p, name="test2_u(1|2)", name_regex=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test2_u1", "test2_u2"], users)

    def test_010_role_intersect(self):
        """User query with role set intersection."""
        q = UserQuery(self.p, roles=["test10a_r", "test10b_r"])

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test10_u1", "test10_u2", "test10_u3",
                              "test10_u4", "test10_u5", "test10_u6"], users)

    def test_011_role_equality(self):
        """User query with role set equality."""
        q = UserQuery(
            self.p, roles=["test11a_r", "test11b_r"], roles_equal=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test11_u2"], users)

    def test_012_role_regex(self):
        """User query with role regex match."""
        q = UserQuery(self.p, roles="test12(a|b)_r", roles_regex=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test12_u1", "test12_u2", "test12_u3",
                              "test12_u4", "test12_u5", "test12_u6"], users)

    def test_020_level_equal(self):
        """User query with default level equality."""
        q = UserQuery(self.p, level="s3:c0,c4")

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test20"], users)

    def test_021_level_dom1(self):
        """User query with default level dominance."""
        q = UserQuery(self.p, level="s2:c1,c2,c4", level_dom=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test21"], users)

    def test_021_level_dom2(self):
        """User query with default level dominance (equal)."""
        q = UserQuery(self.p, level="s2:c1,c4", level_dom=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test21"], users)

    def test_022_level_domby1(self):
        """User query with default level dominated-by."""
        q = UserQuery(self.p, level="s3:c2", level_domby=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test22"], users)

    def test_022_level_domby2(self):
        """User query with default level dominated-by (equal)."""
        q = UserQuery(self.p, level="s3:c2,c4", level_domby=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test22"], users)

    def test_023_level_incomp(self):
        """User query with default level icomparable."""
        q = UserQuery(self.p, level="s5:c0.c5,c7", level_incomp=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test23"], users)

    def test_040_range_exact(self):
        """User query with  range exact match"""
        q = UserQuery(self.p, range_="s0:c5 - s0:c0.c5")

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test40"], users)

    def test_041_range_overlap1(self):
        """User query with range overlap match (equal)"""
        q = UserQuery(self.p, range_="s1:c5 - s1:c1.c3,c5", range_overlap=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test41"], users)

    def test_041_range_overlap2(self):
        """User query with range overlap match (subset)"""
        q = UserQuery(self.p, range_="s1:c2,c5 - s1:c2.c3,c5", range_overlap=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test41"], users)

    def test_041_range_overlap3(self):
        """User query with range overlap match (superset)"""
        q = UserQuery(self.p, range_="s1 - s1:c0.c5", range_overlap=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test41"], users)

    def test_041_range_overlap4(self):
        """User query with range overlap match (overlap low level)"""
        q = UserQuery(self.p, range_="s1:c5 - s1:c2,c5", range_overlap=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test41"], users)

    def test_041_range_overlap5(self):
        """User query with range overlap match (overlap high level)"""
        q = UserQuery(self.p, range_="s1:c5,c2 - s1:c1.c3,c5", range_overlap=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test41"], users)

    def test_042_range_subset1(self):
        """User query with range subset match"""
        q = UserQuery(self.p, range_="s2:c2,c5 - s2:c2.c3,c5", range_overlap=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test42"], users)

    def test_042_range_subset2(self):
        """User query with range subset match (equal)"""
        q = UserQuery(self.p, range_="s2:c5 - s2:c1.c3,c5", range_overlap=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test42"], users)

    def test_043_range_superset1(self):
        """User query with range superset match"""
        q = UserQuery(self.p, range_="s3 - s3:c0.c6", range_superset=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test43"], users)

    def test_043_range_superset2(self):
        """User query with range superset match (equal)"""
        q = UserQuery(self.p, range_="s3:c5 - s3:c1.c3,c5.c6", range_superset=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test43"], users)

    def test_044_range_proper_subset1(self):
        """User query with range proper subset match"""
        q = UserQuery(self.p, range_="s4:c2,c5", range_subset=True, range_proper=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test44"], users)

    def test_044_range_proper_subset2(self):
        """User query with range proper subset match (equal)"""
        q = UserQuery(self.p, range_="s4:c5 - s4:c1.c3,c5", range_subset=True, range_proper=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual([], users)

    def test_044_range_proper_subset3(self):
        """User query with range proper subset match (equal low)"""
        q = UserQuery(self.p, range_="s4:c5 - s4:c1.c2,c5", range_subset=True, range_proper=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test44"], users)

    def test_044_range_proper_subset4(self):
        """User query with range proper subset match (equal high)"""
        q = UserQuery(self.p, range_="s4:c1,c5 - s4:c1.c3,c5", range_subset=True, range_proper=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test44"], users)

    def test_045_range_proper_superset1(self):
        """User query with range proper superset match"""
        q = UserQuery(self.p, range_="s5 - s5:c0.c5", range_superset=True, range_proper=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test45"], users)

    def test_045_range_proper_superset2(self):
        """User query with range proper superset match (equal)"""
        q = UserQuery(self.p, range_="s5:c5 - s5:c1.c3,c5", range_superset=True, range_proper=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual([], users)

    def test_045_range_proper_superset3(self):
        """User query with range proper superset match (equal low)"""
        q = UserQuery(self.p, range_="s5:c5 - s5:c1.c5", range_superset=True, range_proper=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test45"], users)

    def test_045_range_proper_superset4(self):
        """User query with range proper superset match (equal high)"""
        q = UserQuery(self.p, range_="s5 - s5:c1.c3,c5", range_superset=True, range_proper=True)

        users = sorted(str(u) for u in q.results())
        self.assertListEqual(["test45"], users)
