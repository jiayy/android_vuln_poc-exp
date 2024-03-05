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
import stat

from setools import GenfsconQuery

from .policyrep.util import compile_policy


class GenfsconQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/genfsconquery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """Genfscon query with no criteria"""
        # query with no parameters gets all genfs.
        genfs = sorted(self.p.genfscons())

        q = GenfsconQuery(self.p)
        q_genfs = sorted(q.results())

        self.assertListEqual(genfs, q_genfs)

    def test_001_fs_exact(self):
        """Genfscon query with exact fs match"""
        q = GenfsconQuery(self.p, fs="test1", fs_regex=False)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test1"], genfs)

    def test_002_fs_regex(self):
        """Genfscon query with regex fs match"""
        q = GenfsconQuery(self.p, fs="test2(a|b)", fs_regex=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test2a", "test2b"], genfs)

    def test_010_path_exact(self):
        """Genfscon query with exact path match"""
        q = GenfsconQuery(self.p, path="/sys", path_regex=False)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test10"], genfs)

    def test_011_path_regex(self):
        """Genfscon query with regex path match"""
        q = GenfsconQuery(self.p, path="/(spam|eggs)", path_regex=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test11a", "test11b"], genfs)

    def test_020_user_exact(self):
        """Genfscon query with context user exact match"""
        q = GenfsconQuery(self.p, user="user20", user_regex=False)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test20"], genfs)

    def test_021_user_regex(self):
        """Genfscon query with context user regex match"""
        q = GenfsconQuery(self.p, user="user21(a|b)", user_regex=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test21a", "test21b"], genfs)

    def test_030_role_exact(self):
        """Genfscon query with context role exact match"""
        q = GenfsconQuery(self.p, role="role30_r", role_regex=False)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test30"], genfs)

    def test_031_role_regex(self):
        """Genfscon query with context role regex match"""
        q = GenfsconQuery(self.p, role="role31(a|c)_r", role_regex=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test31a", "test31c"], genfs)

    def test_040_type_exact(self):
        """Genfscon query with context type exact match"""
        q = GenfsconQuery(self.p, type_="type40", type_regex=False)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test40"], genfs)

    def test_041_type_regex(self):
        """Genfscon query with context type regex match"""
        q = GenfsconQuery(self.p, type_="type41(b|c)", type_regex=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test41b", "test41c"], genfs)

    def test_050_file_type(self):
        """Genfscon query with file type match"""
        q = GenfsconQuery(self.p, filetype=stat.S_IFBLK)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test50b"], genfs)

    def test_060_range_exact(self):
        """Genfscon query with context range exact match"""
        q = GenfsconQuery(self.p, range_="s0:c1 - s0:c0.c4")

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test60"], genfs)

    def test_061_range_overlap1(self):
        """Genfscon query with context range overlap match (equal)"""
        q = GenfsconQuery(self.p, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test61"], genfs)

    def test_061_range_overlap2(self):
        """Genfscon query with context range overlap match (subset)"""
        q = GenfsconQuery(self.p, range_="s1:c1,c2 - s1:c0.c3", range_overlap=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test61"], genfs)

    def test_061_range_overlap3(self):
        """Genfscon query with context range overlap match (superset)"""
        q = GenfsconQuery(self.p, range_="s1 - s1:c0.c4", range_overlap=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test61"], genfs)

    def test_061_range_overlap4(self):
        """Genfscon query with context range overlap match (overlap low level)"""
        q = GenfsconQuery(self.p, range_="s1 - s1:c1,c2", range_overlap=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test61"], genfs)

    def test_061_range_overlap5(self):
        """Genfscon query with context range overlap match (overlap high level)"""
        q = GenfsconQuery(self.p, range_="s1:c1,c2 - s1:c0.c4", range_overlap=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test61"], genfs)

    def test_062_range_subset1(self):
        """Genfscon query with context range subset match"""
        q = GenfsconQuery(self.p, range_="s2:c1,c2 - s2:c0.c3", range_overlap=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test62"], genfs)

    def test_062_range_subset2(self):
        """Genfscon query with context range subset match (equal)"""
        q = GenfsconQuery(self.p, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test62"], genfs)

    def test_063_range_superset1(self):
        """Genfscon query with context range superset match"""
        q = GenfsconQuery(self.p, range_="s3 - s3:c0.c4", range_superset=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test63"], genfs)

    def test_063_range_superset2(self):
        """Genfscon query with context range superset match (equal)"""
        q = GenfsconQuery(self.p, range_="s3:c1 - s3:c1.c3", range_superset=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test63"], genfs)

    def test_064_range_proper_subset1(self):
        """Genfscon query with context range proper subset match"""
        q = GenfsconQuery(self.p, range_="s4:c1,c2", range_subset=True, range_proper=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test64"], genfs)

    def test_064_range_proper_subset2(self):
        """Genfscon query with context range proper subset match (equal)"""
        q = GenfsconQuery(self.p, range_="s4:c1 - s4:c1.c3", range_subset=True, range_proper=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual([], genfs)

    def test_064_range_proper_subset3(self):
        """Genfscon query with context range proper subset match (equal low only)"""
        q = GenfsconQuery(self.p, range_="s4:c1 - s4:c1.c2", range_subset=True, range_proper=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test64"], genfs)

    def test_064_range_proper_subset4(self):
        """Genfscon query with context range proper subset match (equal high only)"""
        q = GenfsconQuery(self.p,
                          range_="s4:c1,c2 - s4:c1.c3", range_subset=True, range_proper=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test64"], genfs)

    def test_065_range_proper_superset1(self):
        """Genfscon query with context range proper superset match"""
        q = GenfsconQuery(self.p, range_="s5 - s5:c0.c4", range_superset=True, range_proper=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test65"], genfs)

    def test_065_range_proper_superset2(self):
        """Genfscon query with context range proper superset match (equal)"""
        q = GenfsconQuery(self.p, range_="s5:c1 - s5:c1.c3", range_superset=True, range_proper=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual([], genfs)

    def test_065_range_proper_superset3(self):
        """Genfscon query with context range proper superset match (equal low)"""
        q = GenfsconQuery(self.p, range_="s5:c1 - s5:c1.c4", range_superset=True, range_proper=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test65"], genfs)

    def test_065_range_proper_superset4(self):
        """Genfscon query with context range proper superset match (equal high)"""
        q = GenfsconQuery(self.p, range_="s5 - s5:c1.c3", range_superset=True, range_proper=True)

        genfs = sorted(s.fs for s in q.results())
        self.assertListEqual(["test65"], genfs)
