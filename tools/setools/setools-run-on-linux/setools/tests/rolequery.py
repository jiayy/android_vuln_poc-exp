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

from setools import RoleQuery

from .policyrep.util import compile_policy


class RoleQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/rolequery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """Role query with no criteria."""
        # query with no parameters gets all types.
        roles = sorted(self.p.roles())

        q = RoleQuery(self.p)
        q_roles = sorted(q.results())

        self.assertListEqual(roles, q_roles)

    def test_001_name_exact(self):
        """Role query with exact name match."""
        q = RoleQuery(self.p, name="test1")

        roles = sorted(str(r) for r in q.results())
        self.assertListEqual(["test1"], roles)

    def test_002_name_regex(self):
        """Role query with regex name match."""
        q = RoleQuery(self.p, name="test2(a|b)", name_regex=True)

        roles = sorted(str(r) for r in q.results())
        self.assertListEqual(["test2a", "test2b"], roles)

    def test_010_type_intersect(self):
        """Role query with type set intersection."""
        q = RoleQuery(self.p, types=["test10a", "test10b"])

        roles = sorted(str(r) for r in q.results())
        self.assertListEqual(["test10r1", "test10r2", "test10r3",
                              "test10r4", "test10r5", "test10r6"], roles)

    def test_011_type_equality(self):
        """Role query with type set equality."""
        q = RoleQuery(self.p, types=["test11a", "test11b"], types_equal=True)

        roles = sorted(str(r) for r in q.results())
        self.assertListEqual(["test11r2"], roles)

    def test_012_type_regex(self):
        """Role query with type set match."""
        q = RoleQuery(self.p, types="test12(a|b)", types_regex=True)

        roles = sorted(str(r) for r in q.results())
        self.assertListEqual(["test12r1", "test12r2", "test12r3",
                              "test12r4", "test12r5", "test12r6"], roles)
