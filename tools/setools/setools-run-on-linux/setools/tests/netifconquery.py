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

from setools import NetifconQuery

from .policyrep.util import compile_policy


class NetifconQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/netifconquery.conf")

    def test_000_unset(self):
        """Netifcon query with no criteria"""
        # query with no parameters gets all netifs.
        netifs = sorted(self.p.netifcons())

        q = NetifconQuery(self.p)
        q_netifs = sorted(q.results())

        self.assertListEqual(netifs, q_netifs)

    def test_001_name_exact(self):
        """Netifcon query with exact match"""
        q = NetifconQuery(self.p, name="test1", name_regex=False)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test1"], netifs)

    def test_002_name_regex(self):
        """Netifcon query with regex match"""
        q = NetifconQuery(self.p, name="test2(a|b)", name_regex=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test2a", "test2b"], netifs)

    def test_010_user_exact(self):
        """Netifcon query with context user exact match"""
        q = NetifconQuery(self.p, user="user10", user_regex=False)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test10"], netifs)

    def test_011_user_regex(self):
        """Netifcon query with context user regex match"""
        q = NetifconQuery(self.p, user="user11(a|b)", user_regex=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test11a", "test11b"], netifs)

    def test_020_role_exact(self):
        """Netifcon query with context role exact match"""
        q = NetifconQuery(self.p, role="role20_r", role_regex=False)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test20"], netifs)

    def test_021_role_regex(self):
        """Netifcon query with context role regex match"""
        q = NetifconQuery(self.p, role="role21(a|c)_r", role_regex=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test21a", "test21c"], netifs)

    def test_030_type_exact(self):
        """Netifcon query with context type exact match"""
        q = NetifconQuery(self.p, type_="type30", type_regex=False)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test30"], netifs)

    def test_031_type_regex(self):
        """Netifcon query with context type regex match"""
        q = NetifconQuery(self.p, type_="type31(b|c)", type_regex=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test31b", "test31c"], netifs)

    def test_040_range_exact(self):
        """Netifcon query with context range exact match"""
        q = NetifconQuery(self.p, range_="s0:c1 - s0:c0.c4")

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test40"], netifs)

    def test_041_range_overlap1(self):
        """Netifcon query with context range overlap match (equal)"""
        q = NetifconQuery(self.p, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test41"], netifs)

    def test_041_range_overlap2(self):
        """Netifcon query with context range overlap match (subset)"""
        q = NetifconQuery(self.p, range_="s1:c1,c2 - s1:c0.c3", range_overlap=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test41"], netifs)

    def test_041_range_overlap3(self):
        """Netifcon query with context range overlap match (superset)"""
        q = NetifconQuery(self.p, range_="s1 - s1:c0.c4", range_overlap=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test41"], netifs)

    def test_041_range_overlap4(self):
        """Netifcon query with context range overlap match (overlap low level)"""
        q = NetifconQuery(self.p, range_="s1 - s1:c1,c2", range_overlap=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test41"], netifs)

    def test_041_range_overlap5(self):
        """Netifcon query with context range overlap match (overlap high level)"""
        q = NetifconQuery(self.p, range_="s1:c1,c2 - s1:c0.c4", range_overlap=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test41"], netifs)

    def test_042_range_subset1(self):
        """Netifcon query with context range subset match"""
        q = NetifconQuery(self.p, range_="s2:c1,c2 - s2:c0.c3", range_overlap=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test42"], netifs)

    def test_042_range_subset2(self):
        """Netifcon query with context range subset match (equal)"""
        q = NetifconQuery(self.p, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test42"], netifs)

    def test_043_range_superset1(self):
        """Netifcon query with context range superset match"""
        q = NetifconQuery(self.p, range_="s3 - s3:c0.c4", range_superset=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test43"], netifs)

    def test_043_range_superset2(self):
        """Netifcon query with context range superset match (equal)"""
        q = NetifconQuery(self.p, range_="s3:c1 - s3:c1.c3", range_superset=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test43"], netifs)

    def test_044_range_proper_subset1(self):
        """Netifcon query with context range proper subset match"""
        q = NetifconQuery(self.p, range_="s4:c1,c2", range_subset=True, range_proper=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test44"], netifs)

    def test_044_range_proper_subset2(self):
        """Netifcon query with context range proper subset match (equal)"""
        q = NetifconQuery(self.p, range_="s4:c1 - s4:c1.c3", range_subset=True, range_proper=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual([], netifs)

    def test_044_range_proper_subset3(self):
        """Netifcon query with context range proper subset match (equal low only)"""
        q = NetifconQuery(self.p, range_="s4:c1 - s4:c1.c2", range_subset=True, range_proper=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test44"], netifs)

    def test_044_range_proper_subset4(self):
        """Netifcon query with context range proper subset match (equal high only)"""
        q = NetifconQuery(self.p,
                          range_="s4:c1,c2 - s4:c1.c3", range_subset=True, range_proper=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test44"], netifs)

    def test_045_range_proper_superset1(self):
        """Netifcon query with context range proper superset match"""
        q = NetifconQuery(self.p, range_="s5 - s5:c0.c4", range_superset=True, range_proper=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test45"], netifs)

    def test_045_range_proper_superset2(self):
        """Netifcon query with context range proper superset match (equal)"""
        q = NetifconQuery(self.p, range_="s5:c1 - s5:c1.c3", range_superset=True, range_proper=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual([], netifs)

    def test_045_range_proper_superset3(self):
        """Netifcon query with context range proper superset match (equal low)"""
        q = NetifconQuery(self.p, range_="s5:c1 - s5:c1.c4", range_superset=True, range_proper=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test45"], netifs)

    def test_045_range_proper_superset4(self):
        """Netifcon query with context range proper superset match (equal high)"""
        q = NetifconQuery(self.p, range_="s5 - s5:c1.c3", range_superset=True, range_proper=True)

        netifs = sorted(s.netif for s in q.results())
        self.assertListEqual(["test45"], netifs)
