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

from setools import CommonQuery

from .policyrep.util import compile_policy


class CommonQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/commonquery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """Common query with no criteria."""
        # query with no parameters gets all types.
        commons = sorted(self.p.commons())

        q = CommonQuery(self.p)
        q_commons = sorted(q.results())

        self.assertListEqual(commons, q_commons)

    def test_001_name_exact(self):
        """Common query with exact name match."""
        q = CommonQuery(self.p, name="test1")

        commons = sorted(str(c) for c in q.results())
        self.assertListEqual(["test1"], commons)

    def test_002_name_regex(self):
        """Common query with regex name match."""
        q = CommonQuery(self.p, name="test2(a|b)", name_regex=True)

        commons = sorted(str(c) for c in q.results())
        self.assertListEqual(["test2a", "test2b"], commons)

    def test_010_perm_indirect_intersect(self):
        """Common query with intersect permission name patch."""
        q = CommonQuery(self.p, perms=set(["null"]), perms_equal=False)

        commons = sorted(str(c) for c in q.results())
        self.assertListEqual(["test10a", "test10b"], commons)

    def test_011_perm_indirect_equal(self):
        """Common query with equal permission name patch."""
        q = CommonQuery(self.p, perms=set(["read", "write"]), perms_equal=True)

        commons = sorted(str(c) for c in q.results())
        self.assertListEqual(["test11a"], commons)

    def test_012_perm_indirect_regex(self):
        """Common query with regex permission name patch."""
        q = CommonQuery(self.p, perms="sig.+", perms_regex=True)

        commons = sorted(str(c) for c in q.results())
        self.assertListEqual(["test12a", "test12b"], commons)
