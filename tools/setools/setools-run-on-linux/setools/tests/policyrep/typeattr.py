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
from setools.exception import InvalidType, SymbolUseError


@unittest.skip("Needs to be reworked for cython")
class TypeTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = SELinuxPolicy("tests/policyrep/typeattr.conf")

    def mock_type_factory(self, name, attrs=[], alias=[], perm=False):
        """Factory function for Type objects, using a mock qpol object."""
        mock_type = Mock(qpol.qpol_type_t)
        mock_type.name.return_value = name
        mock_type.type_iter.side_effect = AssertionError("Type iterator used")
        mock_type.attr_iter = lambda x: iter(attrs)
        mock_type.alias_iter = lambda x: iter(alias)
        mock_type.ispermissive.return_value = perm
        mock_type.isattr.return_value = False
        mock_type.isalias.return_value = False

        return type_factory(self.p.policy, mock_type)

    def test_001_lookup(self):
        """Type factory policy lookup."""
        type_ = type_factory(self.p.policy, "system")
        self.assertEqual("system", type_.qpol_symbol.name(self.p.policy))

    def test_002_lookup_invalid(self):
        """Type factory policy invalid lookup."""
        with self.assertRaises(InvalidType):
            type_factory(self.p.policy, "INVALID")

    def test_003_lookup_alias(self):
        """Type factory policy lookup alias."""
        type_ = type_factory(self.p.policy, "sysalias", deref=True)
        self.assertEqual("system", type_.qpol_symbol.name(self.p.policy))

    def test_004_lookup_alias_no_deref(self):
        """Type factory policy lookup alias (no dereference)."""
        with self.assertRaises(TypeError):
            type_ = type_factory(self.p.policy, "sysalias")

    def test_005_lookup_attr(self):
        """Type factory policy lookup atribute."""
        with self.assertRaises(TypeError):
            type_ = type_factory(self.p.policy, "attr1")

    def test_006_lookup2(self):
        """Type factory policy lookup (type_or_attr_factory)."""
        type_ = type_or_attr_factory(self.p.policy, "system")
        self.assertEqual("system", type_.qpol_symbol.name(self.p.policy))

    def test_007_lookup2_invalid(self):
        """Type factory policy invalid lookup (type_or_attr_factory)."""
        with self.assertRaises(InvalidType):
            type_or_attr_factory(self.p.policy, "INVALID")

    def test_008_lookup2_alias(self):
        """Type factory policy lookup alias (type_or_attr_factory)."""
        type_ = type_or_attr_factory(self.p.policy, "sysalias", deref=True)
        self.assertEqual("system", type_.qpol_symbol.name(self.p.policy))

    def test_009_lookup2_alias_no_deref(self):
        """Type factory policy lookup alias (no dereference, type_or_attr_factory)."""
        with self.assertRaises(TypeError):
            type_ = type_or_attr_factory(self.p.policy, "sysalias")

    def test_00a_lookup_object(self):
        """Type factory policy lookup of Type object."""
        type1 = type_factory(self.p.policy, "system")
        type2 = type_factory(self.p.policy, type1)
        self.assertIs(type2, type1)

    def test_00b_lookup2_object(self):
        """Type factory policy lookup of Type object (type_or_attr_factory)."""
        type1 = type_or_attr_factory(self.p.policy, "system")
        type2 = type_or_attr_factory(self.p.policy, type1)
        self.assertIs(type2, type1)

    def test_010_string(self):
        """Type basic string rendering."""
        type_ = self.mock_type_factory("name10")
        self.assertEqual("name10", str(type_))

    def test_020_attrs(self):
        """Type attributes"""
        type_ = self.mock_type_factory("name20", attrs=['attr1', 'attr2', 'attr3'])
        self.assertEqual(['attr1', 'attr2', 'attr3'], sorted(type_.attributes()))

    def test_030_aliases(self):
        """Type aliases"""
        type_ = self.mock_type_factory("name30", alias=['alias1', 'alias2', 'alias3'])
        self.assertEqual(['alias1', 'alias2', 'alias3'], sorted(type_.aliases()))

    def test_040_expand(self):
        """Type expansion"""
        type_ = self.mock_type_factory("name40")
        expanded = list(type_.expand())
        self.assertEqual(1, len(expanded))
        self.assertIs(type_, expanded[0])

    def test_050_permissive(self):
        """Type is permissive"""
        type_ = self.mock_type_factory("name50a")
        permtype = self.mock_type_factory("name50b", perm=True)
        self.assertFalse(type_.ispermissive)
        self.assertTrue(permtype.ispermissive)

    def test_060_statement(self):
        """Type basic statement"""
        type_ = self.mock_type_factory("name60")
        self.assertEqual("type name60;", type_.statement())

    def test_061_statement_one_attr(self):
        """Type statement, one attribute"""
        type_ = self.mock_type_factory("name61", attrs=['attr1'])
        self.assertEqual("type name61, attr1;", type_.statement())

    def test_062_statement_two_attr(self):
        """Type statement, two attributes"""
        type_ = self.mock_type_factory("name62", attrs=['attr1', 'attr2'])
        self.assertEqual("type name62, attr1, attr2;", type_.statement())

    def test_063_statement_one_alias(self):
        """Type statement, one alias"""
        type_ = self.mock_type_factory("name63", alias=['alias1'])
        self.assertEqual("type name63 alias alias1;", type_.statement())

    def test_064_statement_two_alias(self):
        """Type statement, two aliases"""
        type_ = self.mock_type_factory("name64", alias=['alias1', 'alias2'])
        self.assertEqual("type name64 alias { alias1 alias2 };", type_.statement())

    def test_065_statement_one_attr_one_alias(self):
        """Type statement, one attribute, one alias"""
        type_ = self.mock_type_factory("name65", attrs=['attr1'], alias=['alias1'])
        self.assertEqual("type name65 alias alias1, attr1;", type_.statement())

    def test_066_statement_two_attr_one_alias(self):
        """Type statement, two attributes, one alias"""
        type_ = self.mock_type_factory("name66", attrs=['attr1', 'attr2'], alias=['alias1'])
        self.assertEqual("type name66 alias alias1, attr1, attr2;", type_.statement())

    def test_067_statement_one_attr_two_alias(self):
        """Type statement, one attribute, two aliases"""
        type_ = self.mock_type_factory("name67", attrs=['attr2'], alias=['alias3', 'alias4'])
        self.assertEqual("type name67 alias { alias3 alias4 }, attr2;", type_.statement())

    def test_068_statement_two_attr_two_alias(self):
        """Type statement, two attributes, two aliases"""
        type_ = self.mock_type_factory("name68", attrs=['attr2', 'attr3'],
                                       alias=['alias2', 'alias4'])
        self.assertEqual("type name68 alias { alias2 alias4 }, attr2, attr3;", type_.statement())


@unittest.skip("Needs to be reworked for cython")
class TypeAttributeTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = SELinuxPolicy("tests/policyrep/typeattr.conf")

    def mock_attr_factory(self, name, types=[]):
        """Factory function for TypeAttribute objects, using a mock qpol object."""
        mock_type = Mock(qpol.qpol_type_t)
        mock_type.name.return_value = name
        mock_type.type_iter = lambda x: iter(types)
        mock_type.attr_iter.side_effect = AssertionError("Attr iter used")
        mock_type.alias_iter.side_effect = AssertionError("Alias iter used")
        mock_type.ispermissive.side_effect = AssertionError("Permissive used")
        mock_type.isattr.return_value = True
        mock_type.isalias.side_effect = AssertionError("Alias used")

        return attribute_factory(self.p.policy, mock_type)

    def test_001_lookup(self):
        """TypeAttribute factory policy lookup."""
        attr = attribute_factory(self.p.policy, "attr1")
        self.assertEqual("attr1", attr.qpol_symbol.name(self.p.policy))

    def test_002_lookup_invalid(self):
        """TypeAttribute factory policy invalid lookup."""
        with self.assertRaises(InvalidType):
            attribute_factory(self.p.policy, "INVALID")

    def test_006_lookup2(self):
        """TypeAttribute factory policy lookup (type_or_attr_factory)."""
        attr = type_or_attr_factory(self.p.policy, "attr1")
        self.assertEqual("attr1", attr.qpol_symbol.name(self.p.policy))

    def test_007_lookup2_invalid(self):
        """TypeAttribute factory policy invalid lookup (type_or_attr_factory)."""
        with self.assertRaises(InvalidType):
            type_or_attr_factory(self.p.policy, "INVALID")

    def test_008_lookup_object(self):
        """TypeAttribute factory policy lookup of TypeAttribute object."""
        attr1 = attribute_factory(self.p.policy, "attr1")
        attr2 = attribute_factory(self.p.policy, attr1)
        self.assertIs(attr2, attr1)

    def test_009_lookup2_object(self):
        """TypeAttribute factory policy lookup of TypeAttribute object (type_or_attr_factory)."""
        attr1 = type_or_attr_factory(self.p.policy, "attr2")
        attr2 = type_or_attr_factory(self.p.policy, attr1)
        self.assertIs(attr2, attr1)

    def test_010_string(self):
        """TypeAttribute basic string rendering."""
        attr = self.mock_attr_factory("name10")
        self.assertEqual("name10", str(attr))

    def test_020_attrs(self):
        """TypeAttribute attributes"""
        attr = self.mock_attr_factory("name20")
        with self.assertRaises(SymbolUseError):
            attr.attributes()

    def test_030_aliases(self):
        """TypeAttribute aliases"""
        attr = self.mock_attr_factory("name30")
        with self.assertRaises(SymbolUseError):
            attr.aliases()

    def test_040_expand(self):
        """TypeAttribute expansion"""
        attr = self.mock_attr_factory("name40", types=['type31a', 'type31b', 'type31c'])
        self.assertEqual(['type31a', 'type31b', 'type31c'], sorted(attr.expand()))

    def test_050_permissive(self):
        with self.assertRaises(SymbolUseError):
            attr = self.mock_attr_factory("name20")
            attr.ispermissive

    def test_060_statement(self):
        """TypeAttribute basic statement"""
        attr = self.mock_attr_factory("name60")
        self.assertEqual("attribute name60;", attr.statement())

    def test_070_contains(self):
        """TypeAttribute: contains"""
        attr = self.mock_attr_factory("name70", types=['type31a', 'type31b', 'type31c'])
        self.assertIn("type31b", attr)
        self.assertNotIn("type30", attr)
