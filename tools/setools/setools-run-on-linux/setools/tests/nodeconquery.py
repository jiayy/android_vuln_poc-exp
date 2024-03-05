# Copyright 2014, Tresys Technology, LLC
# Copyright 2017, Chris PeBenito <pebenito@ieee.org>
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
from socket import AF_INET6
from ipaddress import IPv4Network, IPv6Network

from setools import NodeconQuery

from .policyrep.util import compile_policy


class NodeconQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/nodeconquery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """Nodecon query with no criteria"""
        # query with no parameters gets all nodecons.
        nodecons = sorted(self.p.nodecons())

        q = NodeconQuery(self.p)
        q_nodecons = sorted(q.results())

        self.assertListEqual(nodecons, q_nodecons)

    def test_001_ip_version(self):
        """Nodecon query with IP version match."""
        q = NodeconQuery(self.p, ip_version=AF_INET6)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv6Network("1100::/16"), IPv6Network("1110::/16")], nodecons)

    def test_020_user_exact(self):
        """Nodecon query with context user exact match"""
        q = NodeconQuery(self.p, user="user20", user_regex=False)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.20.1/32")], nodecons)

    def test_021_user_regex(self):
        """Nodecon query with context user regex match"""
        q = NodeconQuery(self.p, user="user21(a|b)", user_regex=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.21.1/32"), IPv4Network("10.1.21.2/32")], nodecons)

    def test_030_role_exact(self):
        """Nodecon query with context role exact match"""
        q = NodeconQuery(self.p, role="role30_r", role_regex=False)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.30.1/32")], nodecons)

    def test_031_role_regex(self):
        """Nodecon query with context role regex match"""
        q = NodeconQuery(self.p, role="role31(a|c)_r", role_regex=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.31.1/32"), IPv4Network("10.1.31.3/32")], nodecons)

    def test_040_type_exact(self):
        """Nodecon query with context type exact match"""
        q = NodeconQuery(self.p, type_="type40", type_regex=False)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.40.1/32")], nodecons)

    def test_041_type_regex(self):
        """Nodecon query with context type regex match"""
        q = NodeconQuery(self.p, type_="type41(b|c)", type_regex=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.41.2/32"), IPv4Network("10.1.41.3/32")], nodecons)

    def test_050_range_exact(self):
        """Nodecon query with context range exact match"""
        q = NodeconQuery(self.p, range_="s0:c1 - s0:c0.c4")

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.50.1/32")], nodecons)

    def test_051_range_overlap1(self):
        """Nodecon query with context range overlap match (equal)"""
        q = NodeconQuery(self.p, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.51.1/32")], nodecons)

    def test_051_range_overlap2(self):
        """Nodecon query with context range overlap match (subset)"""
        q = NodeconQuery(self.p, range_="s1:c1,c2 - s1:c0.c3", range_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.51.1/32")], nodecons)

    def test_051_range_overlap3(self):
        """Nodecon query with context range overlap match (superset)"""
        q = NodeconQuery(self.p, range_="s1 - s1:c0.c4", range_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.51.1/32")], nodecons)

    def test_051_range_overlap4(self):
        """Nodecon query with context range overlap match (overlap low level)"""
        q = NodeconQuery(self.p, range_="s1 - s1:c1,c2", range_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.51.1/32")], nodecons)

    def test_051_range_overlap5(self):
        """Nodecon query with context range overlap match (overlap high level)"""
        q = NodeconQuery(self.p, range_="s1:c1,c2 - s1:c0.c4", range_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.51.1/32")], nodecons)

    def test_052_range_subset1(self):
        """Nodecon query with context range subset match"""
        q = NodeconQuery(self.p, range_="s2:c1,c2 - s2:c0.c3", range_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.52.1/32")], nodecons)

    def test_052_range_subset2(self):
        """Nodecon query with context range subset match (equal)"""
        q = NodeconQuery(self.p, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.52.1/32")], nodecons)

    def test_053_range_superset1(self):
        """Nodecon query with context range superset match"""
        q = NodeconQuery(self.p, range_="s3 - s3:c0.c4", range_superset=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.53.1/32")], nodecons)

    def test_053_range_superset2(self):
        """Nodecon query with context range superset match (equal)"""
        q = NodeconQuery(self.p, range_="s3:c1 - s3:c1.c3", range_superset=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.53.1/32")], nodecons)

    def test_054_range_proper_subset1(self):
        """Nodecon query with context range proper subset match"""
        q = NodeconQuery(self.p, range_="s4:c1,c2", range_subset=True, range_proper=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.54.1/32")], nodecons)

    def test_054_range_proper_subset2(self):
        """Nodecon query with context range proper subset match (equal)"""
        q = NodeconQuery(self.p, range_="s4:c1 - s4:c1.c3", range_subset=True, range_proper=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([], nodecons)

    def test_054_range_proper_subset3(self):
        """Nodecon query with context range proper subset match (equal low only)"""
        q = NodeconQuery(self.p, range_="s4:c1 - s4:c1.c2", range_subset=True, range_proper=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.54.1/32")], nodecons)

    def test_054_range_proper_subset4(self):
        """Nodecon query with context range proper subset match (equal high only)"""
        q = NodeconQuery(self.p, range_="s4:c1,c2 - s4:c1.c3", range_subset=True, range_proper=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.54.1/32")], nodecons)

    def test_055_range_proper_superset1(self):
        """Nodecon query with context range proper superset match"""
        q = NodeconQuery(self.p, range_="s5 - s5:c0.c4", range_superset=True, range_proper=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.55.1/32")], nodecons)

    def test_055_range_proper_superset2(self):
        """Nodecon query with context range proper superset match (equal)"""
        q = NodeconQuery(self.p, range_="s5:c1 - s5:c1.c3", range_superset=True, range_proper=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([], nodecons)

    def test_055_range_proper_superset3(self):
        """Nodecon query with context range proper superset match (equal low)"""
        q = NodeconQuery(self.p, range_="s5:c1 - s5:c1.c4", range_superset=True, range_proper=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.55.1/32")], nodecons)

    def test_055_range_proper_superset4(self):
        """Nodecon query with context range proper superset match (equal high)"""
        q = NodeconQuery(self.p, range_="s5 - s5:c1.c3", range_superset=True, range_proper=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("10.1.55.1/32")], nodecons)

    def test_100_v4network_equal(self):
        """Nodecon query with IPv4 equal network"""
        q = NodeconQuery(self.p, network="192.168.1.0/24", network_overlap=False)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("192.168.1.0/24")], nodecons)

    def test_101_v4network_overlap(self):
        """Nodecon query with IPv4 network overlap"""
        q = NodeconQuery(self.p, network="192.168.201.0/24", network_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv4Network("192.168.200.0/22")], nodecons)

    def test_110_v6network_equal(self):
        """Nodecon query with IPv6 equal network"""
        q = NodeconQuery(self.p, network="1100::/16", network_overlap=False)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv6Network("1100::/16")], nodecons)

    def test_111_v6network_overlap(self):
        """Nodecon query with IPv6 network overlap"""
        q = NodeconQuery(self.p, network="1110:8000::/17", network_overlap=True)

        nodecons = sorted(n.network for n in q.results())
        self.assertListEqual([IPv6Network("1110::/16")], nodecons)
