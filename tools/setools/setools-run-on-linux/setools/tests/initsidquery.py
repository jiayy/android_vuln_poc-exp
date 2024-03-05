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

from setools import InitialSIDQuery

from .policyrep.util import compile_policy


class InitialSIDQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/initsidquery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """Initial SID query with no criteria"""
        # query with no parameters gets all SIDs.
        sids = sorted(self.p.initialsids())

        q = InitialSIDQuery(self.p)
        q_sids = sorted(q.results())

        self.assertListEqual(sids, q_sids)

    def test_001_name_exact(self):
        """Initial SID query with exact match"""
        q = InitialSIDQuery(self.p, name="kernel", name_regex=False)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["kernel"], sids)

    def test_002_name_regex(self):
        """Initial SID query with regex match"""
        q = InitialSIDQuery(self.p, name="(security|unlabeled)", name_regex=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["security", "unlabeled"], sids)

    def test_010_user_exact(self):
        """Initial SID query with context user exact match"""
        q = InitialSIDQuery(self.p, user="user10", user_regex=False)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["fs"], sids)

    def test_011_user_regex(self):
        """Initial SID query with context user regex match"""
        q = InitialSIDQuery(self.p, user="user11(a|b)", user_regex=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["file", "file_labels"], sids)

    def test_020_role_exact(self):
        """Initial SID query with context role exact match"""
        q = InitialSIDQuery(self.p, role="role20_r", role_regex=False)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["any_socket"], sids)

    def test_021_role_regex(self):
        """Initial SID query with context role regex match"""
        q = InitialSIDQuery(self.p, role="role21(a|c)_r", role_regex=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["netmsg", "port"], sids)

    def test_030_type_exact(self):
        """Initial SID query with context type exact match"""
        q = InitialSIDQuery(self.p, type_="type30", type_regex=False)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["node"], sids)

    def test_031_type_regex(self):
        """Initial SID query with context type regex match"""
        q = InitialSIDQuery(self.p, type_="type31(b|c)", type_regex=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["icmp_socket", "tcp_socket"], sids)

    def test_040_range_exact(self):
        """Initial SID query with context range exact match"""
        q = InitialSIDQuery(self.p, range_="s0:c1 - s0:c0.c4")

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["sysctl_modprobe"], sids)

    def test_041_range_overlap1(self):
        """Initial SID query with context range overlap match (equal)"""
        q = InitialSIDQuery(self.p, range_="s1:c1 - s1:c0.c4", range_overlap=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["sysctl"], sids)

    def test_041_range_overlap2(self):
        """Initial SID query with context range overlap match (subset)"""
        q = InitialSIDQuery(self.p, range_="s1:c1,c2 - s1:c0.c3", range_overlap=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["sysctl"], sids)

    def test_041_range_overlap3(self):
        """Initial SID query with context range overlap match (superset)"""
        q = InitialSIDQuery(self.p, range_="s1 - s1:c0.c4", range_overlap=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["sysctl"], sids)

    def test_041_range_overlap4(self):
        """Initial SID query with context range overlap match (overlap low level)"""
        q = InitialSIDQuery(self.p, range_="s1 - s1:c1,c2", range_overlap=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["sysctl"], sids)

    def test_041_range_overlap5(self):
        """Initial SID query with context range overlap match (overlap high level)"""
        q = InitialSIDQuery(self.p, range_="s1:c1,c2 - s1:c0.c4", range_overlap=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["sysctl"], sids)

    def test_042_range_subset1(self):
        """Initial SID query with context range subset match"""
        q = InitialSIDQuery(self.p, range_="s2:c1,c2 - s2:c0.c3", range_overlap=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["sysctl_fs"], sids)

    def test_042_range_subset2(self):
        """Initial SID query with context range subset match (equal)"""
        q = InitialSIDQuery(self.p, range_="s2:c1 - s2:c1.c3", range_overlap=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["sysctl_fs"], sids)

    def test_043_range_superset1(self):
        """Initial SID query with context range superset match"""
        q = InitialSIDQuery(self.p, range_="s3 - s3:c0.c4", range_superset=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["sysctl_kernel"], sids)

    def test_043_range_superset2(self):
        """Initial SID query with context range superset match (equal)"""
        q = InitialSIDQuery(self.p, range_="s3:c1 - s3:c1.c3", range_superset=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["sysctl_kernel"], sids)

    def test_044_range_proper_subset1(self):
        """Initial SID query with context range proper subset match"""
        q = InitialSIDQuery(self.p, range_="s4:c1,c2", range_subset=True, range_proper=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["sysctl_net"], sids)

    def test_044_range_proper_subset2(self):
        """Initial SID query with context range proper subset match (equal)"""
        q = InitialSIDQuery(self.p, range_="s4:c1 - s4:c1.c3", range_subset=True, range_proper=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual([], sids)

    def test_044_range_proper_subset3(self):
        """Initial SID query with context range proper subset match (equal low only)"""
        q = InitialSIDQuery(self.p, range_="s4:c1 - s4:c1.c2", range_subset=True, range_proper=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["sysctl_net"], sids)

    def test_044_range_proper_subset4(self):
        """Initial SID query with context range proper subset match (equal high only)"""
        q = InitialSIDQuery(self.p,
                            range_="s4:c1,c2 - s4:c1.c3", range_subset=True, range_proper=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["sysctl_net"], sids)

    def test_045_range_proper_superset1(self):
        """Initial SID query with context range proper superset match"""
        q = InitialSIDQuery(self.p, range_="s5 - s5:c0.c4", range_superset=True, range_proper=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["sysctl_net_unix"], sids)

    def test_045_range_proper_superset2(self):
        """Initial SID query with context range proper superset match (equal)"""
        q = InitialSIDQuery(self.p,
                            range_="s5:c1 - s5:c1.c3", range_superset=True, range_proper=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual([], sids)

    def test_045_range_proper_superset3(self):
        """Initial SID query with context range proper superset match (equal low)"""
        q = InitialSIDQuery(self.p,
                            range_="s5:c1 - s5:c1.c4", range_superset=True, range_proper=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["sysctl_net_unix"], sids)

    def test_045_range_proper_superset4(self):
        """Initial SID query with context range proper superset match (equal high)"""
        q = InitialSIDQuery(self.p, range_="s5 - s5:c1.c3", range_superset=True, range_proper=True)

        sids = sorted(str(s) for s in q.results())
        self.assertListEqual(["sysctl_net_unix"], sids)
