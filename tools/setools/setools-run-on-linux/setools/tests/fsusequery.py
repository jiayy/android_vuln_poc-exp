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

from setools import FSUseQuery

from .policyrep.util import compile_policy


class FSUseQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/fsusequery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """fs_use_* query with no criteria"""
        # query with no parameters gets all fs_use_*.
        fsu = sorted(self.p.fs_uses())

        q = FSUseQuery(self.p)
        q_fsu = sorted(q.results())

        self.assertListEqual(fsu, q_fsu)

    def test_001_fs_exact(self):
        """fs_use_* query with exact fs match"""
        q = FSUseQuery(self.p, fs="test1", fs_regex=False)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test1"], fsu)

    def test_002_fs_regex(self):
        """fs_use_* query with regex fs match"""
        q = FSUseQuery(self.p, fs="test2(a|b)", fs_regex=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test2a", "test2b"], fsu)

    def test_010_ruletype(self):
        """fs_use_* query with ruletype match"""
        q = FSUseQuery(self.p, ruletype=['fs_use_trans', 'fs_use_task'])

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test10a", "test10b"], fsu)

    def test_020_user_exact(self):
        """fs_use_* query with context user exact match"""
        q = FSUseQuery(self.p, user="user20", user_regex=False)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test20"], fsu)

    def test_021_user_regex(self):
        """fs_use_* query with context user regex match"""
        q = FSUseQuery(self.p, user="user21(a|b)", user_regex=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test21a", "test21b"], fsu)

    def test_030_role_exact(self):
        """fs_use_* query with context role exact match"""
        q = FSUseQuery(self.p, role="role30_r", role_regex=False)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test30"], fsu)

    def test_031_role_regex(self):
        """fs_use_* query with context role regex match"""
        q = FSUseQuery(self.p, role="role31(a|c)_r", role_regex=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test31a", "test31c"], fsu)

    def test_040_type_exact(self):
        """fs_use_* query with context type exact match"""
        q = FSUseQuery(self.p, type_="type40", type_regex=False)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test40"], fsu)

    def test_041_type_regex(self):
        """fs_use_* query with context type regex match"""
        q = FSUseQuery(self.p, type_="type41(b|c)", type_regex=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test41b", "test41c"], fsu)

    def test_050_range_exact(self):
        """fs_use_* query with context range exact match"""
        q = FSUseQuery(self.p, range_="s0:c1 - s0:c0.c4")

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test50"], fsu)

    def test_051_range_overlap1(self):
        """fs_use_* query with context range overlap match (equal)"""
        q = FSUseQuery(self.p, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test51"], fsu)

    def test_051_range_overlap2(self):
        """fs_use_* query with context range overlap match (subset)"""
        q = FSUseQuery(self.p, range_="s1:c1,c2 - s1:c0.c3", range_overlap=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test51"], fsu)

    def test_051_range_overlap3(self):
        """fs_use_* query with context range overlap match (superset)"""
        q = FSUseQuery(self.p, range_="s1 - s1:c0.c4", range_overlap=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test51"], fsu)

    def test_051_range_overlap4(self):
        """fs_use_* query with context range overlap match (overlap low level)"""
        q = FSUseQuery(self.p, range_="s1 - s1:c1,c2", range_overlap=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test51"], fsu)

    def test_051_range_overlap5(self):
        """fs_use_* query with context range overlap match (overlap high level)"""
        q = FSUseQuery(self.p, range_="s1:c1,c2 - s1:c0.c4", range_overlap=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test51"], fsu)

    def test_052_range_subset1(self):
        """fs_use_* query with context range subset match"""
        q = FSUseQuery(self.p, range_="s2:c1,c2 - s2:c0.c3", range_overlap=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test52"], fsu)

    def test_052_range_subset2(self):
        """fs_use_* query with context range subset match (equal)"""
        q = FSUseQuery(self.p, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test52"], fsu)

    def test_053_range_superset1(self):
        """fs_use_* query with context range superset match"""
        q = FSUseQuery(self.p, range_="s3 - s3:c0.c4", range_superset=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test53"], fsu)

    def test_053_range_superset2(self):
        """fs_use_* query with context range superset match (equal)"""
        q = FSUseQuery(self.p, range_="s3:c1 - s3:c1.c3", range_superset=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test53"], fsu)

    def test_054_range_proper_subset1(self):
        """fs_use_* query with context range proper subset match"""
        q = FSUseQuery(self.p, range_="s4:c1,c2", range_subset=True, range_proper=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test54"], fsu)

    def test_054_range_proper_subset2(self):
        """fs_use_* query with context range proper subset match (equal)"""
        q = FSUseQuery(self.p, range_="s4:c1 - s4:c1.c3", range_subset=True, range_proper=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual([], fsu)

    def test_054_range_proper_subset3(self):
        """fs_use_* query with context range proper subset match (equal low only)"""
        q = FSUseQuery(self.p, range_="s4:c1 - s4:c1.c2", range_subset=True, range_proper=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test54"], fsu)

    def test_054_range_proper_subset4(self):
        """fs_use_* query with context range proper subset match (equal high only)"""
        q = FSUseQuery(self.p, range_="s4:c1,c2 - s4:c1.c3", range_subset=True, range_proper=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test54"], fsu)

    def test_055_range_proper_superset1(self):
        """fs_use_* query with context range proper superset match"""
        q = FSUseQuery(self.p, range_="s5 - s5:c0.c4", range_superset=True, range_proper=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test55"], fsu)

    def test_055_range_proper_superset2(self):
        """fs_use_* query with context range proper superset match (equal)"""
        q = FSUseQuery(self.p, range_="s5:c1 - s5:c1.c3", range_superset=True, range_proper=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual([], fsu)

    def test_055_range_proper_superset3(self):
        """fs_use_* query with context range proper superset match (equal low)"""
        q = FSUseQuery(self.p, range_="s5:c1 - s5:c1.c4", range_superset=True, range_proper=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test55"], fsu)

    def test_055_range_proper_superset4(self):
        """fs_use_* query with context range proper superset match (equal high)"""
        q = FSUseQuery(self.p, range_="s5 - s5:c1.c3", range_superset=True, range_proper=True)

        fsu = sorted(s.fs for s in q.results())
        self.assertListEqual(["test55"], fsu)
