# Derived from tests/portconquery.py
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

from setools import IomemconQuery

from .policyrep.util import compile_policy


class IomemconQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/iomemconquery.conf", xen=True)

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """Iomemcon query with no criteria"""
        # query with no parameters gets all addr.
        rules = sorted(self.p.iomemcons())

        q = IomemconQuery(self.p)
        q_rules = sorted(q.results())

        self.assertListEqual(rules, q_rules)

    def test_010_user_exact(self):
        """Iomemcon query with context user exact match"""
        q = IomemconQuery(self.p, user="user10", user_regex=False)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(10, 10)], addr)

    def test_011_user_regex(self):
        """Iomemcon query with context user regex match"""
        q = IomemconQuery(self.p, user="user11(a|b)", user_regex=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(11, 11), (11000, 11000)], addr)

    def test_020_role_exact(self):
        """Iomemcon query with context role exact match"""
        q = IomemconQuery(self.p, role="role20_r", role_regex=False)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(20, 20)], addr)

    def test_021_role_regex(self):
        """Iomemcon query with context role regex match"""
        q = IomemconQuery(self.p, role="role21(a|c)_r", role_regex=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(21, 21), (21001, 21001)], addr)

    def test_030_type_exact(self):
        """Iomemcon query with context type exact match"""
        q = IomemconQuery(self.p, type_="type30", type_regex=False)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(30, 30)], addr)

    def test_031_type_regex(self):
        """Iomemcon query with context type regex match"""
        q = IomemconQuery(self.p, type_="type31(b|c)", type_regex=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(31000, 31000), (31001, 31001)], addr)

    def test_040_range_exact(self):
        """Iomemcon query with context range exact match"""
        q = IomemconQuery(self.p, range_="s0:c1 - s0:c0.c4")

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(40, 40)], addr)

    def test_041_range_overlap1(self):
        """Iomemcon query with context range overlap match (equal)"""
        q = IomemconQuery(self.p, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(41, 41)], addr)

    def test_041_range_overlap2(self):
        """Iomemcon query with context range overlap match (subset)"""
        q = IomemconQuery(self.p, range_="s1:c1,c2 - s1:c0.c3", range_overlap=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(41, 41)], addr)

    def test_041_range_overlap3(self):
        """Iomemcon query with context range overlap match (superset)"""
        q = IomemconQuery(self.p, range_="s1 - s1:c0.c4", range_overlap=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(41, 41)], addr)

    def test_041_range_overlap4(self):
        """Iomemcon query with context range overlap match (overlap low level)"""
        q = IomemconQuery(self.p, range_="s1 - s1:c1,c2", range_overlap=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(41, 41)], addr)

    def test_041_range_overlap5(self):
        """Iomemcon query with context range overlap match (overlap high level)"""
        q = IomemconQuery(self.p, range_="s1:c1,c2 - s1:c0.c4", range_overlap=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(41, 41)], addr)

    def test_042_range_subset1(self):
        """Iomemcon query with context range subset match"""
        q = IomemconQuery(self.p, range_="s2:c1,c2 - s2:c0.c3", range_overlap=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(42, 42)], addr)

    def test_042_range_subset2(self):
        """Iomemcon query with context range subset match (equal)"""
        q = IomemconQuery(self.p, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(42, 42)], addr)

    def test_043_range_superset1(self):
        """Iomemcon query with context range superset match"""
        q = IomemconQuery(self.p, range_="s3 - s3:c0.c4", range_superset=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(43, 43)], addr)

    def test_043_range_superset2(self):
        """Iomemcon query with context range superset match (equal)"""
        q = IomemconQuery(self.p, range_="s3:c1 - s3:c1.c3", range_superset=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(43, 43)], addr)

    def test_044_range_proper_subset1(self):
        """Iomemcon query with context range proper subset match"""
        q = IomemconQuery(self.p, range_="s4:c1,c2", range_subset=True, range_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(44, 44)], addr)

    def test_044_range_proper_subset2(self):
        """Iomemcon query with context range proper subset match (equal)"""
        q = IomemconQuery(self.p, range_="s4:c1 - s4:c1.c3", range_subset=True, range_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([], addr)

    def test_044_range_proper_subset3(self):
        """Iomemcon query with context range proper subset match (equal low only)"""
        q = IomemconQuery(self.p, range_="s4:c1 - s4:c1.c2", range_subset=True, range_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(44, 44)], addr)

    def test_044_range_proper_subset4(self):
        """Iomemcon query with context range proper subset match (equal high only)"""
        q = IomemconQuery(self.p,
                          range_="s4:c1,c2 - s4:c1.c3", range_subset=True, range_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(44, 44)], addr)

    def test_045_range_proper_superset1(self):
        """Iomemcon query with context range proper superset match"""
        q = IomemconQuery(self.p, range_="s5 - s5:c0.c4", range_superset=True, range_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(45, 45)], addr)

    def test_045_range_proper_superset2(self):
        """Iomemcon query with context range proper superset match (equal)"""
        q = IomemconQuery(self.p, range_="s5:c1 - s5:c1.c3", range_superset=True, range_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([], addr)

    def test_045_range_proper_superset3(self):
        """Iomemcon query with context range proper superset match (equal low)"""
        q = IomemconQuery(self.p, range_="s5:c1 - s5:c1.c4", range_superset=True, range_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(45, 45)], addr)

    def test_045_range_proper_superset4(self):
        """Iomemcon query with context range proper superset match (equal high)"""
        q = IomemconQuery(self.p, range_="s5 - s5:c1.c3", range_superset=True, range_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(45, 45)], addr)

    def test_050_single_equal(self):
        """Iomemcon query with single mem addr exact match"""
        q = IomemconQuery(self.p, addr=(50, 50))

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50, 50)], addr)

    def test_051_range_equal(self):
        """Iomemcon query with mem addr range exact match"""
        q = IomemconQuery(self.p, addr=(50100, 50110))

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50100, 50110)], addr)

    def test_052_single_subset(self):
        """Iomemcon query with single mem addr subset"""
        q = IomemconQuery(self.p, addr=(50200, 50200), addr_subset=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50200, 50200)], addr)

    def test_053_range_subset(self):
        """Iomemcon query with range subset"""
        q = IomemconQuery(self.p, addr=(50301, 50309), addr_subset=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50300, 50310)], addr)

    def test_053_range_subset_edge1(self):
        """Iomemcon query with range subset, equal edge case"""
        q = IomemconQuery(self.p, addr=(50300, 50310), addr_subset=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50300, 50310)], addr)

    def test_054_single_proper_subset(self):
        """Iomemcon query with single mem addr proper subset"""
        q = IomemconQuery(
            self.p, addr=(50400, 50400), addr_subset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([], addr)

    def test_055_range_proper_subset(self):
        """Iomemcon query with range proper subset"""
        q = IomemconQuery(
            self.p, addr=(50501, 50509), addr_subset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50500, 50510)], addr)

    def test_055_range_proper_subset_edge1(self):
        """Iomemcon query with range proper subset, equal edge case"""
        q = IomemconQuery(
            self.p, addr=(50500, 50510), addr_subset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([], addr)

    def test_055_range_proper_subset_edge2(self):
        """Iomemcon query with range proper subset, low equal edge case"""
        q = IomemconQuery(
            self.p, addr=(50500, 50509), addr_subset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50500, 50510)], addr)

    def test_055_range_proper_subset_edge3(self):
        """Iomemcon query with range proper subset, high equal edge case"""
        q = IomemconQuery(
            self.p, addr=(50501, 50510), addr_subset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50500, 50510)], addr)

    def test_056_single_superset(self):
        """Iomemcon query with single mem addr superset"""
        q = IomemconQuery(self.p, addr=(50600, 50602), addr_superset=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50601, 50601)], addr)

    def test_056_single_superset_edge1(self):
        """Iomemcon query with single mem addr superset, equal edge case"""
        q = IomemconQuery(self.p, addr=(50601, 50601), addr_superset=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50601, 50601)], addr)

    def test_057_range_superset(self):
        """Iomemcon query with range superset"""
        q = IomemconQuery(self.p, addr=(50700, 50711), addr_superset=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50700, 50710)], addr)

    def test_057_range_superset_edge1(self):
        """Iomemcon query with range superset, equal edge case"""
        q = IomemconQuery(self.p, addr=(50700, 50710), addr_superset=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50700, 50710)], addr)

    def test_058_single_proper_superset(self):
        """Iomemcon query with single mem addr proper superset"""
        q = IomemconQuery(
            self.p, addr=(50800, 50802), addr_superset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50801, 50801)], addr)

    def test_058_single_proper_superset_edge1(self):
        """Iomemcon query with single mem addr proper superset, equal edge case"""
        q = IomemconQuery(
            self.p, addr=(50801, 50801), addr_superset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([], addr)

    def test_058_single_proper_superset_edge2(self):
        """Iomemcon query with single mem addr proper superset, low equal edge case"""
        q = IomemconQuery(
            self.p, addr=(50801, 50802), addr_superset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50801, 50801)], addr)

    def test_058_single_proper_superset_edge3(self):
        """Iomemcon query with single mem addr proper superset, high equal edge case"""
        q = IomemconQuery(
            self.p, addr=(50800, 50801), addr_superset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50801, 50801)], addr)

    def test_059_range_proper_superset(self):
        """Iomemcon query with range proper superset"""
        q = IomemconQuery(
            self.p, addr=(50900, 50911), addr_superset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50901, 50910)], addr)

    def test_059_range_proper_superset_edge1(self):
        """Iomemcon query with range proper superset, equal edge case"""
        q = IomemconQuery(
            self.p, addr=(50901, 50910), addr_superset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([], addr)

    def test_059_range_proper_superset_edge2(self):
        """Iomemcon query with range proper superset, equal high mem addr edge case"""
        q = IomemconQuery(
            self.p, addr=(50900, 50910), addr_superset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50901, 50910)], addr)

    def test_059_range_proper_superset_edge3(self):
        """Iomemcon query with range proper superset, equal low mem addr edge case"""
        q = IomemconQuery(
            self.p, addr=(50901, 50911), addr_superset=True, addr_proper=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(50901, 50910)], addr)

    def test_060_single_overlap(self):
        """Iomemcon query with single overlap"""
        q = IomemconQuery(self.p, addr=(60001, 60001), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(60001, 60001)], addr)

    def test_060_single_overlap_edge1(self):
        """Iomemcon query with single overlap, range match low"""
        q = IomemconQuery(self.p, addr=(60001, 60002), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(60001, 60001)], addr)

    def test_060_single_overlap_edge2(self):
        """Iomemcon query with single overlap, range match high"""
        q = IomemconQuery(self.p, addr=(60000, 60001), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(60001, 60001)], addr)

    def test_060_single_overlap_edge3(self):
        """Iomemcon query with single overlap, range match proper superset"""
        q = IomemconQuery(self.p, addr=(60000, 60002), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(60001, 60001)], addr)

    def test_061_range_overlap_low_half(self):
        """Iomemcon query with range overlap, low half match"""
        q = IomemconQuery(self.p, addr=(60100, 60105), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(60101, 60110)], addr)

    def test_062_range_overlap_high_half(self):
        """Iomemcon query with range overlap, high half match"""
        q = IomemconQuery(self.p, addr=(60205, 60211), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(60200, 60210)], addr)

    def test_063_range_overlap_middle(self):
        """Iomemcon query with range overlap, middle match"""
        q = IomemconQuery(self.p, addr=(60305, 60308), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(60300, 60310)], addr)

    def test_064_range_overlap_equal(self):
        """Iomemcon query with range overlap, equal match"""
        q = IomemconQuery(self.p, addr=(60400, 60410), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(60400, 60410)], addr)

    def test_065_range_overlap_superset(self):
        """Iomemcon query with range overlap, superset match"""
        q = IomemconQuery(self.p, addr=(60500, 60510), addr_overlap=True)

        addr = sorted(p.addr for p in q.results())
        self.assertListEqual([(60501, 60509)], addr)
