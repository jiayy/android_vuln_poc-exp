# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
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

from setools import IbendportconQuery

from .policyrep.util import compile_policy


class IbendportconQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/ibendportconquery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """Ibendportcon query with no criteria"""
        # query with no parameters gets all ibendportcons.
        ibendportcons = sorted(self.p.ibendportcons())

        q = IbendportconQuery(self.p)
        q_ibendportcons = sorted(q.results())

        self.assertListEqual(ibendportcons, q_ibendportcons)

    def test_001_name_exact(self):
        """Ibendportcon query with exact name match."""
        q = IbendportconQuery(self.p, name="test1", name_regex=False)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test1"], ibendportcons)

    def test_002_name_regext(self):
        """Ibendportcon query with regex name match."""
        q = IbendportconQuery(self.p, name="test2(a|b)", name_regex=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test2a", "test2b"], ibendportcons)

    def test_010_port(self):
        """Ibendportcon query with port match."""
        q = IbendportconQuery(self.p, port=10)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test10"], ibendportcons)

    def test_020_user_exact(self):
        """Ibendportcon query with context user exact match"""
        q = IbendportconQuery(self.p, user="user20", user_regex=False)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test20"], ibendportcons)

    def test_021_user_regex(self):
        """Ibendportcon query with context user regex match"""
        q = IbendportconQuery(self.p, user="user21(a|b)", user_regex=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test21a", "test21b"], ibendportcons)

    def test_030_role_exact(self):
        """Ibendportcon query with context role exact match"""
        q = IbendportconQuery(self.p, role="role30_r", role_regex=False)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test30"], ibendportcons)

    def test_031_role_regex(self):
        """Ibendportcon query with context role regex match"""
        q = IbendportconQuery(self.p, role="role31(a|c)_r", role_regex=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test31a", "test31c"], ibendportcons)

    def test_040_type_exact(self):
        """Ibendportcon query with context type exact match"""
        q = IbendportconQuery(self.p, type_="type40", type_regex=False)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test40"], ibendportcons)

    def test_041_type_regex(self):
        """Ibendportcon query with context type regex match"""
        q = IbendportconQuery(self.p, type_="type41(b|c)", type_regex=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test41b", "test41c"], ibendportcons)

    def test_050_range_exact(self):
        """Ibendportcon query with context range exact match"""
        q = IbendportconQuery(self.p, range_="s0:c1 - s0:c0.c4")

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test50"], ibendportcons)

    def test_051_range_overlap1(self):
        """Ibendportcon query with context range overlap match (equal)"""
        q = IbendportconQuery(self.p, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test51"], ibendportcons)

    def test_051_range_overlap2(self):
        """Ibendportcon query with context range overlap match (subset)"""
        q = IbendportconQuery(self.p, range_="s1:c1,c2 - s1:c0.c3", range_overlap=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test51"], ibendportcons)

    def test_051_range_overlap3(self):
        """Ibendportcon query with context range overlap match (superset)"""
        q = IbendportconQuery(self.p, range_="s1 - s1:c0.c4", range_overlap=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test51"], ibendportcons)

    def test_051_range_overlap4(self):
        """Ibendportcon query with context range overlap match (overlap low level)"""
        q = IbendportconQuery(self.p, range_="s1 - s1:c1,c2", range_overlap=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test51"], ibendportcons)

    def test_051_range_overlap5(self):
        """Ibendportcon query with context range overlap match (overlap high level)"""
        q = IbendportconQuery(self.p, range_="s1:c1,c2 - s1:c0.c4", range_overlap=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test51"], ibendportcons)

    def test_052_range_subset1(self):
        """Ibendportcon query with context range subset match"""
        q = IbendportconQuery(self.p, range_="s2:c1,c2 - s2:c0.c3", range_overlap=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test52"], ibendportcons)

    def test_052_range_subset2(self):
        """Ibendportcon query with context range subset match (equal)"""
        q = IbendportconQuery(self.p, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test52"], ibendportcons)

    def test_053_range_superset1(self):
        """Ibendportcon query with context range superset match"""
        q = IbendportconQuery(self.p, range_="s3 - s3:c0.c4", range_superset=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test53"], ibendportcons)

    def test_053_range_superset2(self):
        """Ibendportcon query with context range superset match (equal)"""
        q = IbendportconQuery(self.p, range_="s3:c1 - s3:c1.c3", range_superset=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test53"], ibendportcons)

    def test_054_range_proper_subset1(self):
        """Ibendportcon query with context range proper subset match"""
        q = IbendportconQuery(self.p, range_="s4:c1,c2", range_subset=True, range_proper=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test54"], ibendportcons)

    def test_054_range_proper_subset2(self):
        """Ibendportcon query with context range proper subset match (equal)"""
        q = IbendportconQuery(self.p, range_="s4:c1 - s4:c1.c3", range_subset=True,
                              range_proper=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual([], ibendportcons)

    def test_054_range_proper_subset3(self):
        """Ibendportcon query with context range proper subset match (equal low only)"""
        q = IbendportconQuery(self.p, range_="s4:c1 - s4:c1.c2", range_subset=True,
                              range_proper=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test54"], ibendportcons)

    def test_054_range_proper_subset4(self):
        """Ibendportcon query with context range proper subset match (equal high only)"""
        q = IbendportconQuery(self.p, range_="s4:c1,c2 - s4:c1.c3", range_subset=True,
                              range_proper=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test54"], ibendportcons)

    def test_055_range_proper_superset1(self):
        """Ibendportcon query with context range proper superset match"""
        q = IbendportconQuery(self.p, range_="s5 - s5:c0.c4", range_superset=True,
                              range_proper=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test55"], ibendportcons)

    def test_055_range_proper_superset2(self):
        """Ibendportcon query with context range proper superset match (equal)"""
        q = IbendportconQuery(self.p, range_="s5:c1 - s5:c1.c3", range_superset=True,
                              range_proper=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual([], ibendportcons)

    def test_055_range_proper_superset3(self):
        """Ibendportcon query with context range proper superset match (equal low)"""
        q = IbendportconQuery(self.p, range_="s5:c1 - s5:c1.c4", range_superset=True,
                              range_proper=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test55"], ibendportcons)

    def test_055_range_proper_superset4(self):
        """Ibendportcon query with context range proper superset match (equal high)"""
        q = IbendportconQuery(self.p, range_="s5 - s5:c1.c3", range_superset=True,
                              range_proper=True)

        ibendportcons = sorted(n.name for n in q.results())
        self.assertListEqual(["test55"], ibendportcons)
