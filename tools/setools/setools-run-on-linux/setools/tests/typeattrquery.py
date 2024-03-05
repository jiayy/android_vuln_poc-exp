# Copyright 2014-2015, Tresys Technology, LLC
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

from setools import TypeAttributeQuery

from .policyrep.util import compile_policy


class TypeAttributeQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/typeattrquery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """Type attribute query with no criteria."""
        # query with no parameters gets all attrs.
        allattrs = sorted(self.p.typeattributes())

        q = TypeAttributeQuery(self.p)
        qattrs = sorted(q.results())

        self.assertListEqual(allattrs, qattrs)

    def test_001_name_exact(self):
        """Type attribute query with exact name match."""
        q = TypeAttributeQuery(self.p, name="test1")

        attrs = sorted(str(t) for t in q.results())
        self.assertListEqual(["test1"], attrs)

    def test_002_name_regex(self):
        """Type attribute query with regex name match."""
        q = TypeAttributeQuery(self.p, name="test2(a|b)", name_regex=True)

        attrs = sorted(str(t) for t in q.results())
        self.assertListEqual(["test2a", "test2b"], attrs)

    def test_010_type_set_intersect(self):
        """Type attribute query with type set intersection."""
        q = TypeAttributeQuery(self.p, types=["test10t1", "test10t7"])

        attrs = sorted(str(t) for t in q.results())
        self.assertListEqual(["test10a", "test10c"], attrs)

    def test_011_type_set_equality(self):
        """Type attribute query with type set equality."""
        q = TypeAttributeQuery(self.p, types=["test11t1", "test11t2",
                                              "test11t3", "test11t5"], types_equal=True)

        attrs = sorted(str(t) for t in q.results())
        self.assertListEqual(["test11a"], attrs)

    def test_012_type_set_regex(self):
        """Type attribute query with type set regex match."""
        q = TypeAttributeQuery(self.p, types="test12t(1|2)", types_regex=True)

        attrs = sorted(str(t) for t in q.results())
        self.assertListEqual(["test12a", "test12b"], attrs)
