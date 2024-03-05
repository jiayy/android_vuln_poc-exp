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
# Until this is fixed for cython:
# pylint: disable=undefined-variable
import unittest
from unittest.mock import Mock


@unittest.skip("Needs to be reworked for cython")
class PolCapTest(unittest.TestCase):

    @staticmethod
    def mock_cap(name):
        cap = Mock(qpol.qpol_polcap_t)
        cap.name.return_value = name
        return cap

    def setUp(self):
        self.p = Mock(qpol.qpol_policy_t)

    def test_001_factory(self):
        """PolCap: factory on qpol object."""
        q = self.mock_cap("test1")
        cap = polcap_factory(self.p, q)
        self.assertEqual("test1", cap.qpol_symbol.name(self.p))

    def test_002_factory_object(self):
        """PolCap: factory on PolCap object."""
        q = self.mock_cap("test2")
        cap1 = polcap_factory(self.p, q)
        cap2 = polcap_factory(self.p, cap1)
        self.assertIs(cap2, cap1)

    def test_003_factory_lookup(self):
        """PolCap: factory lookup."""
        with self.assertRaises(TypeError):
            polcap_factory(self.p, "open_perms")

    def test_010_string(self):
        """PolCap: basic string rendering."""
        q = self.mock_cap("test10")
        cap = polcap_factory(self.p, q)
        self.assertEqual("test10", str(cap))

    def test_020_statement(self):
        """PolCap: statement."""
        q = self.mock_cap("test20")
        cap = polcap_factory(self.p, q)
        self.assertEqual("policycap test20;", cap.statement())
