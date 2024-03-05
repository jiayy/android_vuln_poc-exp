# Copyright 2016, Tresys Technology, LLC
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
from unittest.mock import Mock, patch

from setools.exception import InvalidDefaultType, InvalidDefaultValue, \
    InvalidDefaultRange, NoDefaults


@unittest.skip("Needs to be reworked for cython")
@patch('setools.policyrep.objclass.class_factory', lambda x, y: y)
class DefaultTest(unittest.TestCase):

    @staticmethod
    def mock_default(objclass=None, user=None, role=None, type_=None, range_=None):
        d = Mock(qpol_default_object_t)
        d.object_class.return_value = objclass
        d.user_default.return_value = user
        d.role_default.return_value = role
        d.type_default.return_value = type_
        d.range_default.return_value = range_
        return d

    def setUp(self):
        self.p = Mock(qpol_policy_t)

    def test_001_factory_user(self):
        """Default: factory on qpol object with user default."""
        q = self.mock_default("test1", "source")
        defaults = list(default_factory(self.p, q))
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual(DefaultRuletype.default_user, d.ruletype)
        self.assertEqual("test1", d.tclass)
        self.assertEqual(DefaultValue.source, d.default)

    def test_002_factory_role(self):
        """Default: factory on qpol object with role default."""
        q = self.mock_default("test2", role="target")
        defaults = list(default_factory(self.p, q))
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual(DefaultRuletype.default_role, d.ruletype)
        self.assertEqual("test2", d.tclass)
        self.assertEqual(DefaultValue.target, d.default)

    def test_003_factory_type(self):
        """Default: factory on qpol object with type default."""
        q = self.mock_default("test3", type_="source")
        defaults = list(default_factory(self.p, q))
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual(DefaultRuletype.default_type, d.ruletype)
        self.assertEqual("test3", d.tclass)
        self.assertEqual(DefaultValue.source, d.default)

    def test_004_factory_range(self):
        """Default: factory on qpol object with range default."""
        q = self.mock_default("test4", range_="target low_high")
        defaults = list(default_factory(self.p, q))
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual(DefaultRuletype.default_range, d.ruletype)
        self.assertEqual("test4", d.tclass)
        self.assertEqual(DefaultValue.target, d.default)
        self.assertEqual(DefaultRangeValue.low_high, d.default_range)

    def test_005_factory_multiple(self):
        """Default: factory on qpol object with mulitple defaults."""
        q = self.mock_default("test5", "source", "target", "source", "target low")
        defaults = sorted(default_factory(self.p, q))
        self.assertEqual(4, len(defaults))

        d = defaults[0]
        self.assertEqual(DefaultRuletype.default_range, d.ruletype)
        self.assertEqual("test5", d.tclass)

        d = defaults[1]
        self.assertEqual(DefaultRuletype.default_role, d.ruletype)
        self.assertEqual("test5", d.tclass)

        d = defaults[2]
        self.assertEqual(DefaultRuletype.default_type, d.ruletype)
        self.assertEqual("test5", d.tclass)

        d = defaults[3]
        self.assertEqual(DefaultRuletype.default_user, d.ruletype)
        self.assertEqual("test5", d.tclass)

    def test_010_user(self):
        """Default: default_user methods/attributes."""
        q = self.mock_default("test10", "target")
        defaults = list(default_factory(self.p, q))
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual(DefaultRuletype.default_user, d.ruletype)
        self.assertEqual("test10", d.tclass)
        self.assertEqual(DefaultValue.target, d.default)
        self.assertEqual("default_user test10 target;", str(d))
        self.assertEqual(str(d), d.statement())

    def test_011_role(self):
        """Default: default_role methods/attributes."""
        q = self.mock_default("test11", role="source")
        defaults = list(default_factory(self.p, q))
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual(DefaultRuletype.default_role, d.ruletype)
        self.assertEqual("test11", d.tclass)
        self.assertEqual(DefaultValue.source, d.default)
        self.assertEqual("default_role test11 source;", str(d))
        self.assertEqual(str(d), d.statement())

    def test_012_type(self):
        """Default: default_type methods/attributes."""
        q = self.mock_default("test12", type_="target")
        defaults = list(default_factory(self.p, q))
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual(DefaultRuletype.default_type, d.ruletype)
        self.assertEqual("test12", d.tclass)
        self.assertEqual(DefaultValue.target, d.default)
        self.assertEqual("default_type test12 target;", str(d))
        self.assertEqual(str(d), d.statement())

    def test_013_range(self):
        """Default: default_range methods/attributes."""
        q = self.mock_default("test13", range_="source high")
        defaults = list(default_factory(self.p, q))
        self.assertEqual(1, len(defaults))

        d = defaults[0]
        self.assertEqual(DefaultRuletype.default_range, d.ruletype)
        self.assertEqual("test13", d.tclass)
        self.assertEqual(DefaultValue.source, d.default)
        self.assertEqual(DefaultRangeValue.high, d.default_range)
        self.assertEqual("default_range test13 source high;", str(d))
        self.assertEqual(str(d), d.statement())

    @unittest.skip("Default ruletype changed to an enumeration.")
    def test_020_validate_ruletype(self):
        """Default: validate rule type."""
        for r in ["default_user", "default_role", "default_type", "default_range"]:
            self.assertEqual(r, validate_ruletype(r))

    @unittest.skip("Default ruletype changed to an enumeration.")
    def test_021_validate_ruletype_invalid(self):
        """Default: invalid ruletype"""
        with self.assertRaises(InvalidDefaultType):
            validate_ruletype("INVALID")

    @unittest.skip("Default value changed to an enumeration.")
    def test_030_validate_default(self):
        """Default: validate default value."""
        for d in ["source", "target"]:
            self.assertEqual(d, validate_default_value(d))

    @unittest.skip("Default value changed to an enumeration.")
    def test_031_validate_default_invalid(self):
        """Default query: invalid default value"""
        with self.assertRaises(InvalidDefaultValue):
            validate_default_value("INVALID")

    @unittest.skip("Default range value changed to an enumeration.")
    def test_040_validate_default_range(self):
        """Default: validate default range."""
        for r in ["low", "high", "low_high"]:
            self.assertEqual(r, validate_default_range(r))

    @unittest.skip("Default range value changed to an enumeration.")
    def test_041_validate_default_range_invalid(self):
        """Default query: invalid default range"""
        with self.assertRaises(InvalidDefaultRange):
            validate_default_range("INVALID")
