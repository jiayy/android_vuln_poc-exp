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
# pylint: disable=undefined-variable,no-member
import unittest
from unittest.mock import Mock, patch

from setools import SELinuxPolicy
from setools.exception import MLSDisabled, InvalidUser


@unittest.skip("Needs to be reworked for cython")
class UserTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = SELinuxPolicy("tests/policyrep/user.conf")

    def mock_user_factory(self, name, roles, level=None, range_=None):
        """Factory function for User objects, using a mock qpol object."""
        assert (level and range_) or (not level and not range_)

        # inject object_r, like the compiler does
        roles_with_objr = roles
        roles_with_objr.append('object_r')

        mock_user = Mock(qpol.qpol_user_t)
        mock_user.name.return_value = name
        mock_user.role_iter = lambda x: iter(roles_with_objr)
        mock_user.dfltlevel.return_value = level
        mock_user.range.return_value = range_

        return user_factory(self.p.policy, mock_user)

    def test_001_lookup(self):
        """User factory policy lookup."""
        user = user_factory(self.p.policy, "user10")
        self.assertEqual("user10", user.qpol_symbol.name(self.p.policy))

    def test_002_lookup_invalid(self):
        """User factory policy invalid lookup."""
        with self.assertRaises(InvalidUser):
            user_factory(self.p.policy, "INVALID")

    def test_003_lookup_object(self):
        """User factory policy lookup of User object."""
        user1 = user_factory(self.p.policy, "user10")
        user2 = user_factory(self.p.policy, user1)
        self.assertIs(user2, user1)

    def test_010_string(self):
        """User basic string rendering."""
        user = self.mock_user_factory("username", ['role1'])
        self.assertEqual("username", str(user))

    def test_020_statement_role(self):
        """User statement, one role."""
        with patch('setools.policyrep.mls.enabled', return_value=False):
            user = self.mock_user_factory("username", ['role20_r'])
            self.assertEqual("user username roles role20_r;", user.statement())

    def test_021_statement_two_roles(self):
        """User statement, two roles."""
        with patch('setools.policyrep.mls.enabled', return_value=False):
            user = self.mock_user_factory("username", ['role20_r', 'role21a_r'])
            # roles are stored in a set, so the role order may vary
            self.assertRegex(user.statement(), "("
                             "user username roles { role20_r role21a_r };"
                             "|"
                             "user username roles { role21a_r role20_r };"
                             ")")

    def test_022_statement_one_role_mls(self):
        """User statement, one role, MLS."""
        user = self.mock_user_factory("username", ['role20_r'], level="s0", range_="s0-s2")
        self.assertEqual("user username roles role20_r level s0 range s0 - s2;", user.statement())

    def test_023_statement_two_roles_mls(self):
        """User statement, two roles, MLS."""
        user = self.mock_user_factory("username", ['role20_r', 'role21a_r'],
                                      level="s0", range_="s0 - s2")
        # roles are stored in a set, so the role order may vary
        self.assertRegex(
            user.statement(), "("
            "user username roles { role20_r role21a_r } level s0 range s0 - s2;"
            "|"
            "user username roles { role21a_r role20_r } level s0 range s0 - s2;"
            ")")

    def test_030_roles(self):
        """User roles."""
        user = self.mock_user_factory("username", ['role20_r', 'role21a_r'])
        self.assertSetEqual(user.roles, set(['role20_r', 'role21a_r']))

    def test_040_level(self):
        """User level."""
        user = self.mock_user_factory("username", ['role20_r', 'role21a_r'],
                                      level="s0", range_="s0-s2")
        self.assertEqual("s0", user.mls_level)

    def test_041_level_non_mls(self):
        """User level, MLS disabled."""
        user = self.mock_user_factory("username", ['role20_r', 'role21a_r'])
        with patch('setools.policyrep.mls.enabled', return_value=False):
            with self.assertRaises(MLSDisabled):
                user.mls_level

    def test_050_range(self):
        """User level."""
        user = self.mock_user_factory("username", ['role20_r', 'role21a_r'],
                                      level="s0", range_="s0-s2")
        self.assertEqual("s0 - s2", user.mls_range)

    def test_051_range_non_mls(self):
        """User level, MLS disabled."""
        user = self.mock_user_factory("username", ['role20_r', 'role21a_r'],
                                      level="s0", range_="s0-s2")
        with patch('setools.policyrep.mls.enabled', return_value=False):
            with self.assertRaises(MLSDisabled):
                user.mls_range
