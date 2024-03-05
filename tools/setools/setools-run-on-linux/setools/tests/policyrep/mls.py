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
from unittest.mock import Mock

from setools import SELinuxPolicy
from setools.exception import MLSDisabled, InvalidLevel, InvalidLevelDecl, InvalidRange, \
    InvalidSensitivity, InvalidCategory, NoStatement


@unittest.skip("Needs to be reworked for cython")
class SensitivityTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = SELinuxPolicy("tests/policyrep/mls.conf")

    def mock_sens_factory(self, sens, aliases=[]):
        """Factory function for Sensitivity objects, using a mock qpol object."""
        mock_sens = Mock(qpol.qpol_level_t)
        mock_sens.name.return_value = sens
        mock_sens.isalias.return_value = False
        mock_sens.value.return_value = int(sens[1:])
        mock_sens.alias_iter = lambda x: iter(aliases)

        return sensitivity_factory(self.p.policy, mock_sens)

    def test_000_mls_disabled(self):
        """Sensitivity factory on MLS-disabled policy."""
        mock_p = Mock(qpol.qpol_policy_t)
        mock_p.capability.return_value = False
        self.assertRaises(MLSDisabled, sensitivity_factory, mock_p, None)

    def test_001_lookup(self):
        """Sensitivity factory policy lookup."""
        sens = sensitivity_factory(self.p.policy, "s1")
        self.assertEqual("s1", sens.qpol_symbol.name(self.p.policy))

    def test_002_lookup_invalid(self):
        """Sensitivity factory policy invalid lookup."""
        with self.assertRaises(InvalidSensitivity):
            sensitivity_factory(self.p.policy, "INVALID")

    def test_003_lookup_object(self):
        """Sensitivity factory policy lookup of Sensitivity object."""
        sens1 = sensitivity_factory(self.p.policy, "s1")
        sens2 = sensitivity_factory(self.p.policy, sens1)
        self.assertIs(sens2, sens1)

    def test_010_string(self):
        """Sensitivity basic string rendering."""
        sens = self.mock_sens_factory("s0")
        self.assertEqual("s0", str(sens))

    def test_020_statement(self):
        """Sensitivity basic statement rendering."""
        sens = self.mock_sens_factory("s0")
        self.assertEqual("sensitivity s0;", sens.statement())

    def test_021_statement_alias(self):
        """Sensitivity one alias statement rendering."""
        sens = self.mock_sens_factory("s0", ["name1"])
        self.assertEqual("sensitivity s0 alias name1;", sens.statement())

    def test_022_statement_alias(self):
        """Sensitivity two alias statement rendering."""
        sens = self.mock_sens_factory("s0", ["name1", "name2"])
        self.assertEqual("sensitivity s0 alias { name1 name2 };", sens.statement())

    def test_030_value(self):
        """Sensitivity value."""
        sens = self.mock_sens_factory("s17")
        self.assertEqual(17, sens._value)

    def test_031_equal(self):
        """Sensitivity equal."""
        sens1 = self.mock_sens_factory("s0")
        sens2 = self.mock_sens_factory("s0")
        self.assertEqual(sens1, sens2)

    def test_032_equal_str(self):
        """Sensitivity equal to string."""
        sens = self.mock_sens_factory("s17")
        self.assertEqual("s17", sens)

    def test_033_not_equal(self):
        """Sensitivity not equal."""
        sens1 = self.mock_sens_factory("s17")
        sens2 = self.mock_sens_factory("s23")
        self.assertNotEqual(sens1, sens2)

    def test_034_not_equal_str(self):
        """Sensitivity not equal to string."""
        sens = self.mock_sens_factory("s17")
        self.assertNotEqual("s0", sens)

    def test_035_lt(self):
        """Sensitivity less-than."""
        # less
        sens1 = self.mock_sens_factory("s17")
        sens2 = self.mock_sens_factory("s23")
        self.assertTrue(sens1 < sens2)

        # equal
        sens1 = self.mock_sens_factory("s17")
        sens2 = self.mock_sens_factory("s17")
        self.assertFalse(sens1 < sens2)

        # greater
        sens1 = self.mock_sens_factory("s17")
        sens2 = self.mock_sens_factory("s0")
        self.assertFalse(sens1 < sens2)

    def test_036_le(self):
        """Sensitivity less-than-or-equal."""
        # less
        sens1 = self.mock_sens_factory("s17")
        sens2 = self.mock_sens_factory("s23")
        self.assertTrue(sens1 <= sens2)

        # equal
        sens1 = self.mock_sens_factory("s17")
        sens2 = self.mock_sens_factory("s17")
        self.assertTrue(sens1 <= sens2)

        # greater
        sens1 = self.mock_sens_factory("s17")
        sens2 = self.mock_sens_factory("s0")
        self.assertFalse(sens1 <= sens2)

    def test_037_ge(self):
        """Sensitivity greater-than-or-equal."""
        # less
        sens1 = self.mock_sens_factory("s17")
        sens2 = self.mock_sens_factory("s23")
        self.assertFalse(sens1 >= sens2)

        # equal
        sens1 = self.mock_sens_factory("s17")
        sens2 = self.mock_sens_factory("s17")
        self.assertTrue(sens1 >= sens2)

        # greater
        sens1 = self.mock_sens_factory("s17")
        sens2 = self.mock_sens_factory("s0")
        self.assertTrue(sens1 >= sens2)

    def test_038_gt(self):
        """Sensitivity greater-than."""
        # less
        sens1 = self.mock_sens_factory("s17")
        sens2 = self.mock_sens_factory("s23")
        self.assertFalse(sens1 > sens2)

        # equal
        sens1 = self.mock_sens_factory("s17")
        sens2 = self.mock_sens_factory("s17")
        self.assertFalse(sens1 > sens2)

        # greater
        sens1 = self.mock_sens_factory("s17")
        sens2 = self.mock_sens_factory("s0")
        self.assertTrue(sens1 > sens2)


@unittest.skip("Needs to be reworked for cython")
class CategoryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = SELinuxPolicy("tests/policyrep/mls.conf")

    def mock_cat_factory(self, cat, aliases=[]):
        """Factory function for Category objects, using a mock qpol object."""
        mock_cat = Mock(qpol.qpol_cat_t)
        mock_cat.name.return_value = cat
        mock_cat.isalias.return_value = False
        mock_cat.value.return_value = int(cat[1:])
        mock_cat.alias_iter = lambda x: iter(aliases)

        return category_factory(self.p.policy, mock_cat)

    def test_000_mls_disabled(self):
        """Category factory on MLS-disabled policy."""
        mock_p = Mock(qpol.qpol_policy_t)
        mock_p.capability.return_value = False
        self.assertRaises(MLSDisabled, category_factory, mock_p, None)

    def test_001_lookup(self):
        """Category factory policy lookup."""
        cat = category_factory(self.p.policy, "c1")
        self.assertEqual("c1", cat.qpol_symbol.name(self.p.policy))

    def test_002_lookup_invalid(self):
        """Category factory policy invalid lookup."""
        with self.assertRaises(InvalidCategory):
            category_factory(self.p.policy, "INVALID")

    def test_003_lookup_object(self):
        """Category factory policy lookup of Category object."""
        cat1 = category_factory(self.p.policy, "c1")
        cat2 = category_factory(self.p.policy, cat1)
        self.assertIs(cat2, cat1)

    def test_010_statement(self):
        """Category basic string rendering."""
        cat = self.mock_cat_factory("c0")
        self.assertEqual("c0", str(cat))

    def test_020_statement(self):
        """Category basic statement rendering."""
        cat = self.mock_cat_factory("c0")
        self.assertEqual("category c0;", cat.statement())

    def test_021_statement_alias(self):
        """Category one alias statement rendering."""
        cat = self.mock_cat_factory("c0", ["name1"])
        self.assertEqual("category c0 alias name1;", cat.statement())

    def test_022_statement_alias(self):
        """Category two alias statement rendering."""
        cat = self.mock_cat_factory("c0", ["name1", "name2"])
        self.assertEqual("category c0 alias { name1 name2 };", cat.statement())

    def test_030_value(self):
        """Category value."""
        cat = self.mock_cat_factory("c17")
        self.assertEqual(17, cat._value)


@unittest.skip("Needs to be reworked for cython")
class LevelDeclTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = SELinuxPolicy("tests/policyrep/mls.conf")

    def mock_decl_factory(self, sens, cats=[]):
        """Factory function for LevelDecl objects, using a mock qpol object."""
        mock_decl = Mock(qpol.qpol_level_t)
        mock_decl.name.return_value = sens
        mock_decl.isalias.return_value = False
        mock_decl.value.return_value = int(sens[1:])
        mock_decl.cat_iter = lambda x: iter(cats)

        return level_decl_factory(self.p.policy, mock_decl)

    def test_000_mls_disabled(self):
        """Level declaration factory on MLS-disabled policy."""
        mock_p = Mock(qpol.qpol_policy_t)
        mock_p.capability.return_value = False
        self.assertRaises(MLSDisabled, level_decl_factory, mock_p, None)

    def test_001_lookup(self):
        """Level declaration factory policy lookup."""
        decl = level_decl_factory(self.p.policy, "s1")
        self.assertEqual("s1", decl.qpol_symbol.name(self.p.policy))

    def test_002_lookup_invalid(self):
        """Level declaration factory policy invalid lookup."""
        with self.assertRaises(InvalidLevelDecl):
            level_decl_factory(self.p.policy, "INVALID")

    def test_003_lookup_object(self):
        """Level declaration factory policy lookup of LevelDecl object."""
        level1 = level_decl_factory(self.p.policy, "s1")
        level2 = level_decl_factory(self.p.policy, level1)
        self.assertIs(level2, level1)

    def test_010_string(self):
        """Level declaration basic string rendering."""
        decl = self.mock_decl_factory("s0")
        self.assertEqual("s0", str(decl))

    def test_011_string_single_cat(self):
        """Level declaration string rendering with one category"""
        decl = self.mock_decl_factory("s0", ["c0"])
        self.assertEqual("s0:c0", str(decl))

    def test_012_string_multiple_cat(self):
        """Level declaration string rendering with multiple categories"""
        decl = self.mock_decl_factory("s0", ["c0", "c3"])
        self.assertEqual("s0:c0,c3", str(decl))

    def test_013_string_cat_set(self):
        """Level declaration string rendering with category set"""
        decl = self.mock_decl_factory("s0", ["c0", "c1", "c2", "c3"])
        self.assertEqual("s0:c0.c3", str(decl))

    def test_014_string_complex(self):
        """Level declaration string rendering with complex category set"""
        decl = self.mock_decl_factory("s0", ["c0", "c1", "c2", "c3", "c5", "c7", "c8", "c9"])
        self.assertEqual("s0:c0.c3,c5,c7.c9", str(decl))

    def test_020_statement(self):
        """Level declaration basic statement rendering."""
        decl = self.mock_decl_factory("s0")
        self.assertEqual("level s0;", decl.statement())

    def test_021_statement_single_cat(self):
        """Level declaration statement rendering with one category"""
        decl = self.mock_decl_factory("s0", ["c0"])
        self.assertEqual("level s0:c0;", decl.statement())

    def test_022_statement_multiple_cat(self):
        """Level declaration statement rendering with multiple categories"""
        decl = self.mock_decl_factory("s0", ["c0", "c3"])
        self.assertEqual("level s0:c0,c3;", decl.statement())

    def test_012_string_cat_set(self):
        """Level declaration statement rendering with category set"""
        decl = self.mock_decl_factory("s0", ["c0", "c1", "c2", "c3"])
        self.assertEqual("level s0:c0.c3;", decl.statement())

    def test_013_statement_complex(self):
        """Level declaration statement rendering with complex category set"""
        decl = self.mock_decl_factory("s0", ["c0", "c1", "c2", "c3", "c5", "c7", "c8", "c9"])
        self.assertEqual("level s0:c0.c3,c5,c7.c9;", decl.statement())

    def test_030_equal(self):
        """Level declaration equal."""
        decl1 = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        decl2 = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        self.assertEqual(decl1, decl2)

    def test_031_equal_str(self):
        """Level declaration equal to string."""
        decl = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        self.assertEqual("s17:c0.c3", decl)

    def test_032_not_equal(self):
        """Level declaration not equal."""
        decl1 = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        decl2 = self.mock_decl_factory("s23")
        self.assertNotEqual(decl1, decl2)

    def test_033_not_equal_str(self):
        """Level declaration not equal to string."""
        decl = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        self.assertNotEqual("s0:c0.c2", decl)

    def test_034_lt(self):
        """Level declaration less-than."""
        # less
        decl1 = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        decl2 = self.mock_decl_factory("s23", ["c7", "c8", "c9"])
        self.assertTrue(decl1 < decl2)

        # equal
        decl1 = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        decl2 = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        self.assertFalse(decl1 < decl2)

        # greater
        decl1 = self.mock_decl_factory("s24")
        decl2 = self.mock_decl_factory("s23", ["c7", "c8", "c9"])
        self.assertFalse(decl1 < decl2)

    def test_035_le(self):
        """Level declaration less-than-or-equal."""
        # less
        decl1 = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        decl2 = self.mock_decl_factory("s23", ["c7", "c8", "c9"])
        self.assertTrue(decl1 <= decl2)

        # equal
        decl1 = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        decl2 = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        self.assertTrue(decl1 <= decl2)

        # greater
        decl1 = self.mock_decl_factory("s24")
        decl2 = self.mock_decl_factory("s23", ["c7", "c8", "c9"])
        self.assertFalse(decl1 <= decl2)

    def test_036_ge(self):
        """Level declaration greater-than-or-equal."""
        # less
        decl1 = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        decl2 = self.mock_decl_factory("s23", ["c7", "c8", "c9"])
        self.assertFalse(decl1 >= decl2)

        # equal
        decl1 = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        decl2 = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        self.assertTrue(decl1 >= decl2)

        # greater
        decl1 = self.mock_decl_factory("s24")
        decl2 = self.mock_decl_factory("s23", ["c7", "c8", "c9"])
        self.assertTrue(decl1 >= decl2)

    def test_037_gt(self):
        """Level declaration greater-than."""
        # less
        decl1 = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        decl2 = self.mock_decl_factory("s23", ["c7", "c8", "c9"])
        self.assertFalse(decl1 > decl2)

        # equal
        decl1 = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        decl2 = self.mock_decl_factory("s17", ["c0", "c1", "c2", "c3"])
        self.assertFalse(decl1 > decl2)

        # greater
        decl1 = self.mock_decl_factory("s24")
        decl2 = self.mock_decl_factory("s23", ["c7", "c8", "c9"])
        self.assertTrue(decl1 > decl2)


@unittest.skip("Needs to be reworked for cython")
class LevelTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = SELinuxPolicy("tests/policyrep/mls.conf")

    def mock_level_factory(self, sens, cats=[]):
        """Factory function Level objects, using a mock qpol object."""
        mock_level = Mock(qpol.qpol_mls_level_t)
        mock_level.sens_name.return_value = sens
        mock_level.cat_iter = lambda x: iter(cats)

        return level_factory(self.p.policy, mock_level)

    def test_000_mls_disabled(self):
        """Level factory on MLS-disabled policy."""
        mock_p = Mock(qpol.qpol_policy_t)
        mock_p.capability.return_value = False
        self.assertRaises(MLSDisabled, level_factory, mock_p, None)

    def test_001_lookup_no_cats(self):
        """Level lookup with no categories."""
        levelobj = level_factory(self.p.policy, "s2")
        self.assertEqual("s2", levelobj.qpol_symbol.sens_name(self.p.policy))
        self.assertEqual(str(levelobj), "s2")

    def test_002_lookup_cat_range(self):
        """Level lookup with category range."""
        levelobj = level_factory(self.p.policy, "s1:c0.c13")
        self.assertEqual(str(levelobj), "s1:c0.c13")

    def test_003_lookup_complex_cats(self):
        """Level lookup with complex category set."""
        levelobj = level_factory(self.p.policy, "s2:c0.c5,c7,c9.c11,c13")
        self.assertEqual(str(levelobj), "s2:c0.c5,c7,c9.c11,c13")

    def test_004_lookup_bad1(self):
        """Level lookup with garbage."""
        self.assertRaises(InvalidLevel, level_factory, self.p.policy, "FAIL")

    def test_005_lookup_bad2(self):
        """Level lookup with : in garbage."""
        self.assertRaises(InvalidLevel, level_factory, self.p.policy, "FAIL:BAD")

    def test_006_lookup_bad_cat(self):
        """Level lookup with invalid category."""
        self.assertRaises(InvalidLevel, level_factory, self.p.policy, "s0:FAIL")

    def test_007_lookup_bad_cat_range(self):
        """Level lookup with backwards category range."""
        self.assertRaises(InvalidLevel, level_factory, self.p.policy, "s0:c4.c0")

    def test_008_lookup_cat_range_error(self):
        """Level lookup with category range parse error."""
        self.assertRaises(InvalidLevel, level_factory, self.p.policy, "s0:c0.c2.c4")

    def test_009_lookup_cat_not_assoc(self):
        """Level lookup with category not associated with sensitivity."""
        # c4 is not associated with s0.
        self.assertRaises(InvalidLevel, level_factory, self.p.policy, "s0:c0,c4")

    def test_00a_lookup_object(self):
        """Level factory policy lookup of Level object."""
        level1 = level_factory(self.p.policy, "s0")
        level2 = level_factory(self.p.policy, level1)
        self.assertIs(level2, level1)

    def test_010_equal(self):
        """Level equal."""
        level1 = self.mock_level_factory("s0", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s0", ["c0", "c1", "c2", "c3"])
        self.assertEqual(level1, level2)

    def test_011_equal_str(self):
        """Level equal to string."""
        level = self.mock_level_factory("s2", ["c0", "c1", "c2", "c3"])
        self.assertEqual("s2:c0.c3", level)

    def test_012_not_equal(self):
        """Level not equal."""
        level1 = self.mock_level_factory("s0", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s0")
        self.assertNotEqual(level1, level2)

    def test_013_not_equal_str(self):
        """Level not equal to string."""
        level = self.mock_level_factory("s0", ["c0", "c2"])
        self.assertNotEqual("s0:c0.c2", level)

    def test_014_dom(self):
        """Level dominate (ge)."""
        # equal
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertTrue(level1 >= level2)

        # sens dominate
        level1 = self.mock_level_factory("s2", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertTrue(level1 >= level2)

        # cat set dominate
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3", "c4"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertTrue(level1 >= level2)

        # sens domby
        level1 = self.mock_level_factory("s0", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertFalse(level1 >= level2)

        # cat set domby
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertFalse(level1 >= level2)

        # incomp
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2"])
        level2 = self.mock_level_factory("s1", ["c7", "c8", "c9"])
        self.assertFalse(level1 >= level2)

    def test_015_domby(self):
        """Level dominate-by (le)."""
        # equal
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertTrue(level1 <= level2)

        # sens dominate
        level1 = self.mock_level_factory("s2", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertFalse(level1 <= level2)

        # cat set dominate
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3", "c4"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertFalse(level1 <= level2)

        # sens domby
        level1 = self.mock_level_factory("s0", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertTrue(level1 <= level2)

        # cat set domby
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertTrue(level1 <= level2)

        # incomp
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2"])
        level2 = self.mock_level_factory("s1", ["c7", "c8", "c9"])
        self.assertFalse(level1 <= level2)

    def test_016_proper_dom(self):
        """Level proper dominate (gt)."""
        # equal
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertFalse(level1 > level2)

        # sens dominate
        level1 = self.mock_level_factory("s2", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertTrue(level1 > level2)

        # cat set dominate
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3", "c4"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertTrue(level1 > level2)

        # sens domby
        level1 = self.mock_level_factory("s0", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertFalse(level1 > level2)

        # cat set domby
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertFalse(level1 > level2)

        # incomp
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2"])
        level2 = self.mock_level_factory("s1", ["c7", "c8", "c9"])
        self.assertFalse(level1 > level2)

    def test_017_proper_domby(self):
        """Level proper dominate-by (lt)."""
        # equal
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertFalse(level1 < level2)

        # sens dominate
        level1 = self.mock_level_factory("s2", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertFalse(level1 < level2)

        # cat set dominate
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3", "c4"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertFalse(level1 < level2)

        # sens domby
        level1 = self.mock_level_factory("s0", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertTrue(level1 < level2)

        # cat set domby
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertTrue(level1 < level2)

        # incomp
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2"])
        level2 = self.mock_level_factory("s1", ["c7", "c8", "c9"])
        self.assertFalse(level1 < level2)

    def test_018_incomp(self):
        """Level incomparable (xor)."""
        # equal
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertFalse(level1 ^ level2)

        # sens dominate
        level1 = self.mock_level_factory("s2", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertFalse(level1 ^ level2)

        # cat set dominate
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3", "c4"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertFalse(level1 ^ level2)

        # sens domby
        level1 = self.mock_level_factory("s0", ["c0", "c1", "c2", "c3"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertFalse(level1 ^ level2)

        # cat set domby
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2"])
        level2 = self.mock_level_factory("s1", ["c0", "c1", "c2", "c3"])
        self.assertFalse(level1 ^ level2)

        # incomp
        level1 = self.mock_level_factory("s1", ["c0", "c1", "c2"])
        level2 = self.mock_level_factory("s1", ["c7", "c8", "c9"])
        self.assertTrue(level1 ^ level2)

    def test_020_level_statement(self):
        """Level has no statement."""
        level = self.mock_level_factory("s1")
        with self.assertRaises(NoStatement):
            level.statement()


@unittest.skip("Needs to be reworked for cython")
class RangeTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.p = SELinuxPolicy("tests/policyrep/mls.conf")

    def test_000_mls_disabled(self):
        """Range factory on MLS-disabled policy."""
        mock_p = Mock(qpol.qpol_policy_t)
        mock_p.capability.return_value = False
        self.assertRaises(MLSDisabled, range_factory, mock_p, None)

    def test_001_range_lookup_single_level(self):
        """Range lookup with single-level range."""
        rangeobj = range_factory(self.p.policy, "s0")
        self.assertEqual(str(rangeobj), "s0")

    def test_002_range_lookup_single_level_redundant(self):
        """Range lookup with single-level range (same range listed twice)."""
        rangeobj = range_factory(self.p.policy, "s1-s1")
        self.assertEqual(str(rangeobj), "s1")

    def test_003_range_lookup_simple(self):
        """Range lookup with simple range."""
        rangeobj = range_factory(self.p.policy, "s0-s1:c0.c10")
        self.assertEqual(str(rangeobj), "s0 - s1:c0.c10")

    def test_004_range_lookup_no_cats(self):
        """Range lookup with no categories."""
        rangeobj = range_factory(self.p.policy, "s0-s1")
        self.assertEqual(str(rangeobj), "s0 - s1")

    def test_005_range_lookup_complex(self):
        """Range lookup with complex category set."""
        rangeobj = range_factory(self.p.policy, "s0:c0.c2-s2:c0.c5,c7,c9.c11,c13")
        self.assertEqual(str(rangeobj), "s0:c0.c2 - s2:c0.c5,c7,c9.c11,c13")

    def test_006_range_lookup_non_dom(self):
        """Range lookup with non-dominating high level."""
        self.assertRaises(InvalidRange, range_factory, self.p.policy, "s1-s0")

    def test_007_range_lookup_invalid_range_low(self):
        """Range lookup with an invalid range (low)."""
        # c13 is not associated with s0.
        self.assertRaises(InvalidRange, range_factory, self.p.policy, "s0:c13-s2:c13")

    def test_008_range_lookup_invalid_range_high(self):
        """Range lookup with an invalid range (high)."""
        # c13 is not associated with s0.
        self.assertRaises(InvalidRange, range_factory, self.p.policy, "s0-s0:c13")

    def test_009_lookup_object(self):
        """Range factory policy lookup of Range object."""
        range1 = range_factory(self.p.policy, "s0")
        range2 = range_factory(self.p.policy, range1)
        self.assertIs(range2, range1)

    def test_020_equal(self):
        """Range equality."""
        rangeobj1 = range_factory(self.p.policy, "s0:c0.c2-s2:c0.c5,c7,c9.c11,c13")
        rangeobj2 = range_factory(self.p.policy, "s0:c0.c2-s2:c0.c5,c7,c9.c11,c13")
        self.assertEqual(rangeobj1, rangeobj2)

    def test_021_equal(self):
        """Range equal to string."""
        rangeobj = range_factory(self.p.policy, "s0:c0.c2-s2:c0.c5,c7,c9.c11,c13")
        self.assertEqual("s0:c0.c2-s2:c0.c5,c7,c9.c11,c13", rangeobj)
        self.assertEqual("s0:c0.c2- s2:c0.c5,c7,c9.c11,c13", rangeobj)
        self.assertEqual("s0:c0.c2 -s2:c0.c5,c7,c9.c11,c13", rangeobj)
        self.assertEqual("s0:c0.c2 - s2:c0.c5,c7,c9.c11,c13", rangeobj)

    def test_022_contains(self):
        """Range contains a level."""
        rangeobj = range_factory(self.p.policy, "s0:c1-s2:c0.c10")

        # too low
        level1 = level_factory(self.p.policy, "s0")
        self.assertNotIn(level1, rangeobj)

        # low level
        level2 = level_factory(self.p.policy, "s0:c1")
        self.assertIn(level2, rangeobj)

        # mid
        level3 = level_factory(self.p.policy, "s1:c1,c5")
        self.assertIn(level3, rangeobj)

        # high level
        level4 = level_factory(self.p.policy, "s2:c0.c10")
        self.assertIn(level4, rangeobj)

        # too high
        level5 = level_factory(self.p.policy, "s2:c0.c11")
        self.assertNotIn(level5, rangeobj)

    def test_030_range_statement(self):
        """Range has no statement."""
        rangeobj = range_factory(self.p.policy, "s0")
        with self.assertRaises(NoStatement):
            rangeobj.statement()
