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

from setools import PolCapQuery

from .policyrep.util import compile_policy


class PolCapQueryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/polcapquery.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def test_000_unset(self):
        """Policy capability query with no criteria"""
        # query with no parameters gets all capabilities.
        allcaps = sorted(self.p.polcaps())

        q = PolCapQuery(self.p)
        qcaps = sorted(q.results())

        self.assertListEqual(allcaps, qcaps)

    def test_001_name_exact(self):
        """Policy capability query with exact match"""
        q = PolCapQuery(self.p, name="open_perms", name_regex=False)

        caps = sorted(str(c) for c in q.results())
        self.assertListEqual(["open_perms"], caps)

    def test_002_name_regex(self):
        """Policy capability query with regex match"""
        q = PolCapQuery(self.p, name="pe?er", name_regex=True)

        caps = sorted(str(c) for c in q.results())
        self.assertListEqual(["network_peer_controls", "open_perms"], caps)
