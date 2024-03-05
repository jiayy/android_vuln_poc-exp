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

from setools import IbpkeyconQuery

from .policyrep.util import compile_policy


class IbpkeyconQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/ibpkeyconquery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """ibpkeycon query with no criteria"""
        # query with no parameters gets all ibpkeycons.
        ibpkeycons = sorted(self.p.ibpkeycons())

        q = IbpkeyconQuery(self.p)
        q_ibpkeycons = sorted(q.results())

        self.assertListEqual(ibpkeycons, q_ibpkeycons)

    def test_001_subnet_mask(self):
        """Ibpkeycon query with subnet mask match."""
        q = IbpkeyconQuery(self.p, subnet_prefix="fe81::")

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(1, 1)], ibpkeycons)

    def test_010_pkey_exact(self):
        """Ibpkeycon query with exact pkey match."""
        q = IbpkeyconQuery(self.p, pkeys=(0x10c, 0x10e))

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(0x10c, 0x10e)], ibpkeycons)

    def test_020_user_exact(self):
        """ibpkeycon query with context user exact match"""
        q = IbpkeyconQuery(self.p, user="user20", user_regex=False)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(20, 20)], ibpkeycons)

    def test_021_user_regex(self):
        """ibpkeycon query with context user regex match"""
        q = IbpkeyconQuery(self.p, user="user21(a|b)", user_regex=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(0x21a, 0x21a), (0x21b, 0x21b)], ibpkeycons)

    def test_030_role_exact(self):
        """ibpkeycon query with context role exact match"""
        q = IbpkeyconQuery(self.p, role="role30_r", role_regex=False)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(30, 30)], ibpkeycons)

    def test_031_role_regex(self):
        """ibpkeycon query with context role regex match"""
        q = IbpkeyconQuery(self.p, role="role31(a|c)_r", role_regex=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(0x31a, 0x31a), (0x31c, 0x31c)], ibpkeycons)

    def test_040_type_exact(self):
        """ibpkeycon query with context type exact match"""
        q = IbpkeyconQuery(self.p, type_="type40", type_regex=False)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(40, 40)], ibpkeycons)

    def test_041_type_regex(self):
        """ibpkeycon query with context type regex match"""
        q = IbpkeyconQuery(self.p, type_="type41(b|c)", type_regex=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(0x41b, 0x41b), (0x41c, 0x41c)], ibpkeycons)

    def test_050_range_exact(self):
        """ibpkeycon query with context range exact match"""
        q = IbpkeyconQuery(self.p, range_="s0:c1 - s0:c0.c4")

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(50, 50)], ibpkeycons)

    def test_051_range_overlap1(self):
        """ibpkeycon query with context range overlap match (equal)"""
        q = IbpkeyconQuery(self.p, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(51, 51)], ibpkeycons)

    def test_051_range_overlap2(self):
        """ibpkeycon query with context range overlap match (subset)"""
        q = IbpkeyconQuery(self.p, range_="s1:c1,c2 - s1:c0.c3", range_overlap=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(51, 51)], ibpkeycons)

    def test_051_range_overlap3(self):
        """ibpkeycon query with context range overlap match (superset)"""
        q = IbpkeyconQuery(self.p, range_="s1 - s1:c0.c4", range_overlap=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(51, 51)], ibpkeycons)

    def test_051_range_overlap4(self):
        """ibpkeycon query with context range overlap match (overlap low level)"""
        q = IbpkeyconQuery(self.p, range_="s1 - s1:c1,c2", range_overlap=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(51, 51)], ibpkeycons)

    def test_051_range_overlap5(self):
        """ibpkeycon query with context range overlap match (overlap high level)"""
        q = IbpkeyconQuery(self.p, range_="s1:c1,c2 - s1:c0.c4", range_overlap=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(51, 51)], ibpkeycons)

    def test_052_range_subset1(self):
        """ibpkeycon query with context range subset match"""
        q = IbpkeyconQuery(self.p, range_="s2:c1,c2 - s2:c0.c3", range_overlap=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(52, 52)], ibpkeycons)

    def test_052_range_subset2(self):
        """ibpkeycon query with context range subset match (equal)"""
        q = IbpkeyconQuery(self.p, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(52, 52)], ibpkeycons)

    def test_053_range_superset1(self):
        """ibpkeycon query with context range superset match"""
        q = IbpkeyconQuery(self.p, range_="s3 - s3:c0.c4", range_superset=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(53, 53)], ibpkeycons)

    def test_053_range_superset2(self):
        """ibpkeycon query with context range superset match (equal)"""
        q = IbpkeyconQuery(self.p, range_="s3:c1 - s3:c1.c3", range_superset=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(53, 53)], ibpkeycons)

    def test_054_range_proper_subset1(self):
        """ibpkeycon query with context range proper subset match"""
        q = IbpkeyconQuery(self.p, range_="s4:c1,c2", range_subset=True, range_proper=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(54, 54)], ibpkeycons)

    def test_054_range_proper_subset2(self):
        """ibpkeycon query with context range proper subset match (equal)"""
        q = IbpkeyconQuery(self.p, range_="s4:c1 - s4:c1.c3", range_subset=True, range_proper=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([], ibpkeycons)

    def test_054_range_proper_subset3(self):
        """ibpkeycon query with context range proper subset match (equal low only)"""
        q = IbpkeyconQuery(self.p, range_="s4:c1 - s4:c1.c2", range_subset=True, range_proper=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(54, 54)], ibpkeycons)

    def test_054_range_proper_subset4(self):
        """ibpkeycon query with context range proper subset match (equal high only)"""
        q = IbpkeyconQuery(self.p, range_="s4:c1,c2 - s4:c1.c3", range_subset=True,
                           range_proper=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(54, 54)], ibpkeycons)

    def test_055_range_proper_superset1(self):
        """ibpkeycon query with context range proper superset match"""
        q = IbpkeyconQuery(self.p, range_="s5 - s5:c0.c4", range_superset=True, range_proper=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(55, 55)], ibpkeycons)

    def test_055_range_proper_superset2(self):
        """ibpkeycon query with context range proper superset match (equal)"""
        q = IbpkeyconQuery(self.p, range_="s5:c1 - s5:c1.c3", range_superset=True,
                           range_proper=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([], ibpkeycons)

    def test_055_range_proper_superset3(self):
        """ibpkeycon query with context range proper superset match (equal low)"""
        q = IbpkeyconQuery(self.p, range_="s5:c1 - s5:c1.c4", range_superset=True,
                           range_proper=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(55, 55)], ibpkeycons)

    def test_055_range_proper_superset4(self):
        """ibpkeycon query with context range proper superset match (equal high)"""
        q = IbpkeyconQuery(self.p, range_="s5 - s5:c1.c3", range_superset=True,
                           range_proper=True)

        ibpkeycons = sorted(n.pkeys for n in q.results())
        self.assertListEqual([(55, 55)], ibpkeycons)

    def test_900_invalid_subnet_prefix(self):
        """Ibpkeycon query with invalid subnet prefix"""
        with self.assertRaises(ValueError):
            IbpkeyconQuery(self.p, subnet_prefix="INVALID")

    def test_910_invalid_pkey_negative(self):
        """Ibpkeycon query with negative pkey"""
        with self.assertRaises(ValueError):
            IbpkeyconQuery(self.p, pkeys=(-1, -1))

        with self.assertRaises(ValueError):
            IbpkeyconQuery(self.p, pkeys=(1, -1))

        with self.assertRaises(ValueError):
            IbpkeyconQuery(self.p, pkeys=(-1, 1))

    def test_911_invalid_pkey_zero(self):
        """Ibpkeycon query with 0 pkey"""
        with self.assertRaises(ValueError):
            IbpkeyconQuery(self.p, pkeys=(0, 0))

    def test_912_invalid_pkey_over_max(self):
        """Ibpkeycon query with pkey over maximum value"""
        with self.assertRaises(ValueError):
            IbpkeyconQuery(self.p, pkeys=(1, 0xfffff))

        with self.assertRaises(ValueError):
            IbpkeyconQuery(self.p, pkeys=(0xfffff, 1))

        with self.assertRaises(ValueError):
            IbpkeyconQuery(self.p, pkeys=(0xfffff, 0xfffff))

    def test_913_invalid_pkey_not_a_number(self):
        """Ibpkeycon query with pkey is not a number"""
        with self.assertRaises(TypeError):
            IbpkeyconQuery(self.p, pkeys=(1, "INVALID"))

        with self.assertRaises(TypeError):
            IbpkeyconQuery(self.p, pkeys=("INVALID", 2))

    def test_914_invalid_pkey_not_tuple(self):
        """Ibpkeycon query with pkey is not a tuple"""
        with self.assertRaises(TypeError):
            IbpkeyconQuery(self.p, pkeys=1)

    def test_915_invalid_pkey_wrong_tuple_length(self):
        """Ibpkeycon query with pkey is not correct tuple size"""
        with self.assertRaises(TypeError):
            IbpkeyconQuery(self.p, pkeys=(1,))

        with self.assertRaises(TypeError):
            IbpkeyconQuery(self.p, pkeys=(1, 2, 3))
