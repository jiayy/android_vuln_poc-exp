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

from setools import ObjClassQuery

from .policyrep.util import compile_policy


class ObjClassQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/objclassquery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """Class query with no criteria."""
        # query with no parameters gets all types.
        classes = sorted(self.p.classes())

        q = ObjClassQuery(self.p)
        q_classes = sorted(q.results())

        self.assertListEqual(classes, q_classes)

    def test_001_name_exact(self):
        """Class query with exact name match."""
        q = ObjClassQuery(self.p, name="infoflow")

        classes = sorted(str(c) for c in q.results())
        self.assertListEqual(["infoflow"], classes)

    def test_002_name_regex(self):
        """Class query with regex name match."""
        q = ObjClassQuery(self.p, name="infoflow(2|3)", name_regex=True)

        classes = sorted(str(c) for c in q.results())
        self.assertListEqual(["infoflow2", "infoflow3"], classes)

    def test_010_common_exact(self):
        """Class query with exact common name match."""
        q = ObjClassQuery(self.p, common="infoflow")

        classes = sorted(str(c) for c in q.results())
        self.assertListEqual(["infoflow", "infoflow2",
                              "infoflow4", "infoflow7"], classes)

    def test_011_common_regex(self):
        """Class query with regex common name match."""
        q = ObjClassQuery(self.p, common="com_[ab]", common_regex=True)

        classes = sorted(str(c) for c in q.results())
        self.assertListEqual(["infoflow5", "infoflow6"], classes)

    def test_020_perm_indirect_intersect(self):
        """Class query with indirect, intersect permission name patch."""
        q = ObjClassQuery(
            self.p, perms=set(["send"]), perms_indirect=True, perms_equal=False)

        classes = sorted(str(c) for c in q.results())
        self.assertListEqual(["infoflow6"], classes)

    def test_021_perm_direct_intersect(self):
        """Class query with direct, intersect permission name patch."""
        q = ObjClassQuery(
            self.p, perms=set(["super_r"]), perms_indirect=False, perms_equal=False)

        classes = sorted(str(c) for c in q.results())
        self.assertListEqual(["infoflow2", "infoflow4", "infoflow8"], classes)

    def test_022_perm_indirect_equal(self):
        """Class query with indirect, equal permission name patch."""
        q = ObjClassQuery(self.p, perms=set(
            ["low_w", "med_w", "hi_w", "low_r", "med_r", "hi_r", "unmapped"]),
            perms_indirect=True, perms_equal=True)

        classes = sorted(str(c) for c in q.results())
        self.assertListEqual(["infoflow7"], classes)

    def test_023_perm_direct_equal(self):
        """Class query with direct, equal permission name patch."""
        q = ObjClassQuery(self.p, perms=set(
            ["super_r", "super_w"]), perms_indirect=False, perms_equal=True)

        classes = sorted(str(c) for c in q.results())
        self.assertListEqual(["infoflow2", "infoflow8"], classes)

    def test_024_perm_indirect_regex(self):
        """Class query with indirect, regex permission name patch."""
        q = ObjClassQuery(
            self.p, perms="(send|setattr)", perms_indirect=True, perms_regex=True)

        classes = sorted(str(c) for c in q.results())
        self.assertListEqual(["infoflow6", "infoflow9"], classes)

    def test_025_perm_direct_regex(self):
        """Class query with direct, regex permission name patch."""
        q = ObjClassQuery(
            self.p, perms="(read|super_r)", perms_indirect=False, perms_regex=True)

        classes = sorted(str(c) for c in q.results())
        self.assertListEqual(["infoflow10", "infoflow2",
                              "infoflow4", "infoflow8"],
                             classes)
