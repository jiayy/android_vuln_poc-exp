# Copyright 2015, Tresys Technology, LLC
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

from setools import SensitivityQuery

from .policyrep.util import compile_policy


class SensitivityQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/sensitivityquery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """Sensitivity query with no criteria."""
        # query with no parameters gets all sensitivities.
        allsens = sorted(str(c) for c in self.p.sensitivities())

        q = SensitivityQuery(self.p)
        qsens = sorted(str(c) for c in q.results())

        self.assertListEqual(allsens, qsens)

    def test_001_name_exact(self):
        """Sensitivity query with exact name match."""
        q = SensitivityQuery(self.p, name="test1")

        sens = sorted(str(c) for c in q.results())
        self.assertListEqual(["test1"], sens)

    def test_002_name_regex(self):
        """Sensitivity query with regex name match."""
        q = SensitivityQuery(self.p, name="test2(a|b)", name_regex=True)

        sens = sorted(str(c) for c in q.results())
        self.assertListEqual(["test2a", "test2b"], sens)

    def test_010_alias_exact(self):
        """Sensitivity query with exact alias match."""
        q = SensitivityQuery(self.p, alias="test10a")

        sens = sorted(str(t) for t in q.results())
        self.assertListEqual(["test10s1"], sens)

    def test_011_alias_regex(self):
        """Sensitivity query with regex alias match."""
        q = SensitivityQuery(self.p, alias="test11(a|b)", alias_regex=True)

        sens = sorted(str(t) for t in q.results())
        self.assertListEqual(["test11s1", "test11s2"], sens)

    def test_020_sens_equal(self):
        """Sensitivity query with sens equality."""
        q = SensitivityQuery(self.p, sens="test20")

        sens = sorted(str(u) for u in q.results())
        self.assertListEqual(["test20"], sens)

    def test_021_sens_dom1(self):
        """Sensitivity query with sens dominance."""
        q = SensitivityQuery(self.p, sens="test21crit", sens_dom=True)

        sens = sorted(str(u) for u in q.results())
        self.assertListEqual(["test21", "test21crit"], sens)

    def test_021_sens_dom2(self):
        """Sensitivity query with sens dominance (equal)."""
        q = SensitivityQuery(self.p, sens="test21", sens_dom=True)

        sens = sorted(str(u) for u in q.results())
        self.assertListEqual(["test21"], sens)

    def test_022_sens_domby1(self):
        """Sensitivity query with sens dominated-by."""
        q = SensitivityQuery(self.p, sens="test22crit", sens_domby=True)

        sens = sorted(str(u) for u in q.results())
        self.assertListEqual(["test22", "test22crit"], sens)

    def test_022_sens_domby2(self):
        """Sensitivity query with sens dominated-by (equal)."""
        q = SensitivityQuery(self.p, sens="test22", sens_domby=True)

        sens = sorted(str(u) for u in q.results())
        self.assertListEqual(["test22"], sens)
