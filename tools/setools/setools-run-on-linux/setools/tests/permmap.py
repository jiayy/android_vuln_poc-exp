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
import unittest
import os
from unittest.mock import Mock

from setools import PermissionMap, TERuletype
from setools.exception import PermissionMapParseError, RuleTypeError, \
    UnmappedClass, UnmappedPermission

from .policyrep.util import compile_policy


class PermissionMapTest(unittest.TestCase):

    """Permission map unit tests."""

    @classmethod
    def setUpClass(cls):
        cls.p = compile_policy("tests/permmap.conf")

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.p.path)

    def validate_permmap_entry(self, permmap, cls, perm, direction, weight, enabled):
        """Validate a permission map entry and settings."""
        self.assertIn(cls, permmap)
        self.assertIn(perm, permmap[cls])
        self.assertIn('direction', permmap[cls][perm])
        self.assertIn('weight', permmap[cls][perm])
        self.assertIn('enabled', permmap[cls][perm])
        self.assertEqual(permmap[cls][perm]['direction'], direction)
        self.assertEqual(permmap[cls][perm]['weight'], weight)

        if enabled:
            self.assertTrue(permmap[cls][perm]['enabled'])
        else:
            self.assertFalse(permmap[cls][perm]['enabled'])

    def test_001_load(self):
        """PermMap open from path."""
        permmap = PermissionMap("tests/perm_map")

        # validate permission map contents
        self.assertEqual(5, len(permmap.permmap))

        # class infoflow
        self.assertIn("infoflow", permmap.permmap)
        self.assertEqual(6, len(permmap.permmap['infoflow']))
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'low_w', 'w', 1, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'med_w', 'w', 5, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'hi_w', 'w', 10, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'low_r', 'r', 1, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'med_r', 'r', 5, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'hi_r', 'r', 10, True)

        # class infoflow2
        self.assertIn("infoflow2", permmap.permmap)
        self.assertEqual(7, len(permmap.permmap['infoflow2']))
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'low_w', 'w', 1, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'med_w', 'w', 5, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'hi_w', 'w', 10, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'low_r', 'r', 1, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'med_r', 'r', 5, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'hi_r', 'r', 10, True)
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'super', 'b', 10, True)

        # class infoflow3
        self.assertIn("infoflow3", permmap.permmap)
        self.assertEqual(1, len(permmap.permmap['infoflow3']))
        self.validate_permmap_entry(permmap.permmap, 'infoflow3', 'null', 'n', 1, True)

        # class file
        self.assertIn("file", permmap.permmap)
        self.assertEqual(2, len(permmap.permmap['file']))
        self.validate_permmap_entry(permmap.permmap, 'file', 'execute', 'r', 10, True)
        self.validate_permmap_entry(permmap.permmap, 'file', 'entrypoint', 'r', 10, True)

        # class process
        self.assertIn("process", permmap.permmap)
        self.assertEqual(1, len(permmap.permmap['process']))
        self.validate_permmap_entry(permmap.permmap, 'process', 'transition', 'w', 10, True)

    def test_002_load_invalid(self):
        """PermMap load completely wrong file type"""
        with self.assertRaises(PermissionMapParseError):
            PermissionMap("setup.py")

    def test_002_load_negative_class_count(self):
        """PermMap load negative class count"""
        with self.assertRaises(PermissionMapParseError):
            PermissionMap("tests/invalid_perm_maps/negative-classcount")

    def test_003_load_non_number_class_count(self):
        """PermMap load non-number class count"""
        with self.assertRaises(PermissionMapParseError):
            PermissionMap("tests/invalid_perm_maps/non-number-classcount")

    def test_004_load_extra_class(self):
        """PermMap load extra class"""
        with self.assertRaises(PermissionMapParseError):
            PermissionMap("tests/invalid_perm_maps/extra-class")

    def test_005_load_bad_class_keyword(self):
        """PermMap load bad class keyword"""
        with self.assertRaises(PermissionMapParseError):
            PermissionMap("tests/invalid_perm_maps/bad-class-keyword")

    # test 6: bad class name(?)

    def test_007_load_negative_perm_count(self):
        """PermMap load negative permission count"""
        with self.assertRaises(PermissionMapParseError):
            PermissionMap("tests/invalid_perm_maps/negative-permcount")

    def test_008_load_bad_perm_count(self):
        """PermMap load bad permission count"""
        with self.assertRaises(PermissionMapParseError):
            PermissionMap("tests/invalid_perm_maps/bad-permcount")

    # test 9: bad perm name(?)

    def test_010_load_extra_perms(self):
        """PermMap load negative permission count"""
        with self.assertRaises(PermissionMapParseError):
            PermissionMap("tests/invalid_perm_maps/extra-perms")

    def test_011_load_invalid_flow_direction(self):
        """PermMap load invalid flow direction"""
        with self.assertRaises(PermissionMapParseError):
            PermissionMap("tests/invalid_perm_maps/invalid-flowdir")

    def test_012_load_bad_perm_weight(self):
        """PermMap load too high/low permission weight"""
        with self.assertRaises(PermissionMapParseError):
            PermissionMap("tests/invalid_perm_maps/bad-perm-weight-high")

        with self.assertRaises(PermissionMapParseError):
            PermissionMap("tests/invalid_perm_maps/bad-perm-weight-low")

    def test_013_load_invalid_weight(self):
        """PermMap load invalid permission weight"""
        with self.assertRaises(PermissionMapParseError):
            PermissionMap("tests/invalid_perm_maps/invalid-perm-weight")

    def test_100_set_weight(self):
        """PermMap set weight"""
        permmap = PermissionMap("tests/perm_map")
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'low_w', 'w', 1, True)
        permmap.set_weight("infoflow2", "low_w", 10)
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'low_w', 'w', 10, True)

    def test_101_set_weight_low(self):
        """PermMap set weight low"""
        permmap = PermissionMap("tests/perm_map")
        with self.assertRaises(ValueError):
            permmap.set_weight("infoflow2", "low_w", 0)

        with self.assertRaises(ValueError):
            permmap.set_weight("infoflow2", "low_w", -10)

    def test_102_set_weight_low(self):
        """PermMap set weight high"""
        permmap = PermissionMap("tests/perm_map")
        with self.assertRaises(ValueError):
            permmap.set_weight("infoflow2", "low_w", 11)

        with self.assertRaises(ValueError):
            permmap.set_weight("infoflow2", "low_w", 50)

    def test_103_set_weight_unmapped_class(self):
        """PermMap set weight unmapped class"""
        permmap = PermissionMap("tests/perm_map")
        with self.assertRaises(UnmappedClass):
            permmap.set_weight("UNMAPPED", "write", 10)

    def test_104_set_weight_unmapped_permission(self):
        """PermMap set weight unmapped class"""
        permmap = PermissionMap("tests/perm_map")
        with self.assertRaises(UnmappedPermission):
            permmap.set_weight("infoflow2", "UNMAPPED", 10)

    def test_110_set_direction(self):
        """PermMap set direction"""
        permmap = PermissionMap("tests/perm_map")
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'low_w', 'w', 1, True)
        permmap.set_direction("infoflow2", "low_w", "r")
        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'low_w', 'r', 1, True)

    def test_111_set_direction_invalid(self):
        """PermMap set invalid direction"""
        permmap = PermissionMap("tests/perm_map")
        with self.assertRaises(ValueError):
            permmap.set_direction("infoflow2", "low_w", "X")

    def test_112_set_direction_unmapped_class(self):
        """PermMap set direction unmapped class"""
        permmap = PermissionMap("tests/perm_map")
        with self.assertRaises(UnmappedClass):
            permmap.set_direction("UNMAPPED", "write", "w")

    def test_113_set_direction_unmapped_permission(self):
        """PermMap set direction unmapped class"""
        permmap = PermissionMap("tests/perm_map")
        with self.assertRaises(UnmappedPermission):
            permmap.set_direction("infoflow2", "UNMAPPED", "w")

    def test_120_exclude_perm(self):
        """PermMap exclude permission."""
        permmap = PermissionMap("tests/perm_map")
        permmap.exclude_permission("infoflow", "med_w")
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'med_w', 'w', 5, False)

    def test_121_exclude_perm_unmapped_class(self):
        """PermMap exclude permission unmapped class."""
        permmap = PermissionMap("tests/perm_map")
        with self.assertRaises(UnmappedClass):
            permmap.exclude_permission("UNMAPPED", "med_w")

    def test_122_exclude_perm_unmapped_perm(self):
        """PermMap exclude permission unmapped permission."""
        permmap = PermissionMap("tests/perm_map")
        with self.assertRaises(UnmappedPermission):
            permmap.exclude_permission("infoflow", "UNMAPPED")

    def test_123_include_perm(self):
        """PermMap include permission."""
        permmap = PermissionMap("tests/perm_map")
        permmap.exclude_permission("infoflow", "med_w")
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'med_w', 'w', 5, False)

        permmap.include_permission("infoflow", "med_w")
        self.validate_permmap_entry(permmap.permmap, 'infoflow', 'med_w', 'w', 5, True)

    def test_124_include_perm_unmapped_class(self):
        """PermMap include permission unmapped class."""
        permmap = PermissionMap("tests/perm_map")
        with self.assertRaises(UnmappedClass):
            permmap.include_permission("UNMAPPED", "med_w")

    def test_125_include_perm_unmapped_perm(self):
        """PermMap include permission unmapped permission."""
        permmap = PermissionMap("tests/perm_map")
        with self.assertRaises(UnmappedPermission):
            permmap.include_permission("infoflow", "UNMAPPED")

    def test_130_exclude_class(self):
        """PermMap exclude class."""
        permmap = PermissionMap("tests/perm_map")
        permmap.exclude_class("file")
        self.validate_permmap_entry(permmap.permmap, 'file', 'execute', 'r', 10, False)
        self.validate_permmap_entry(permmap.permmap, 'file', 'entrypoint', 'r', 10, False)

    def test_131_exclude_class_unmapped_class(self):
        """PermMap exclude class unmapped class."""
        permmap = PermissionMap("tests/perm_map")
        with self.assertRaises(UnmappedClass):
            permmap.exclude_class("UNMAPPED")

    def test_132_include_class(self):
        """PermMap exclude class."""
        permmap = PermissionMap("tests/perm_map")
        permmap.exclude_class("file")
        self.validate_permmap_entry(permmap.permmap, 'file', 'execute', 'r', 10, False)
        self.validate_permmap_entry(permmap.permmap, 'file', 'entrypoint', 'r', 10, False)

        permmap.include_class("file")
        self.validate_permmap_entry(permmap.permmap, 'file', 'execute', 'r', 10, True)
        self.validate_permmap_entry(permmap.permmap, 'file', 'entrypoint', 'r', 10, True)

    def test_133_include_class_unmapped_class(self):
        """PermMap include class unmapped class."""
        permmap = PermissionMap("tests/perm_map")
        with self.assertRaises(UnmappedClass):
            permmap.include_class("UNMAPPED")

    def test_140_weight_read_only(self):
        """PermMap get weight of read-only rule."""
        rule = Mock()
        rule.ruletype = TERuletype.allow
        rule.tclass = "infoflow"
        rule.perms = set(["med_r", "hi_r"])

        permmap = PermissionMap("tests/perm_map")
        r, w = permmap.rule_weight(rule)
        self.assertEqual(r, 10)
        self.assertEqual(w, 0)

    def test_141_weight_write_only(self):
        """PermMap get weight of write-only rule."""
        rule = Mock()
        rule.ruletype = TERuletype.allow
        rule.tclass = "infoflow"
        rule.perms = set(["low_w", "med_w"])

        permmap = PermissionMap("tests/perm_map")
        r, w = permmap.rule_weight(rule)
        self.assertEqual(r, 0)
        self.assertEqual(w, 5)

    def test_142_weight_both(self):
        """PermMap get weight of both rule."""
        rule = Mock()
        rule.ruletype = TERuletype.allow
        rule.tclass = "infoflow"
        rule.perms = set(["low_r", "hi_w"])

        permmap = PermissionMap("tests/perm_map")
        r, w = permmap.rule_weight(rule)
        self.assertEqual(r, 1)
        self.assertEqual(w, 10)

    def test_143_weight_none(self):
        """PermMap get weight of none rule."""
        rule = Mock()
        rule.ruletype = TERuletype.allow
        rule.tclass = "infoflow3"
        rule.perms = set(["null"])

        permmap = PermissionMap("tests/perm_map")
        r, w = permmap.rule_weight(rule)
        self.assertEqual(r, 0)
        self.assertEqual(w, 0)

    def test_144_weight_unmapped_class(self):
        """PermMap get weight of rule with unmapped class."""
        rule = Mock()
        rule.ruletype = TERuletype.allow
        rule.tclass = "unmapped"
        rule.perms = set(["null"])

        permmap = PermissionMap("tests/perm_map")
        self.assertRaises(UnmappedClass, permmap.rule_weight, rule)

    def test_145_weight_unmapped_permission(self):
        """PermMap get weight of rule with unmapped permission."""
        rule = Mock()
        rule.ruletype = TERuletype.allow
        rule.tclass = "infoflow"
        rule.perms = set(["low_r", "unmapped"])

        permmap = PermissionMap("tests/perm_map")
        self.assertRaises(UnmappedPermission, permmap.rule_weight, rule)

    def test_146_weight_wrong_rule_type(self):
        """PermMap get weight of rule with wrong rule type."""
        rule = Mock()
        rule.ruletype = TERuletype.type_transition
        rule.tclass = "infoflow"

        permmap = PermissionMap("tests/perm_map")
        self.assertRaises(RuleTypeError, permmap.rule_weight, rule)

    def test_147_weight_excluded_permission(self):
        """PermMap get weight of a rule with excluded permission."""
        rule = Mock()
        rule.ruletype = TERuletype.allow
        rule.tclass = "infoflow"
        rule.perms = set(["med_r", "hi_r"])

        permmap = PermissionMap("tests/perm_map")
        permmap.exclude_permission("infoflow", "hi_r")
        r, w = permmap.rule_weight(rule)
        self.assertEqual(r, 5)
        self.assertEqual(w, 0)

    def test_148_weight_excluded_class(self):
        """PermMap get weight of a rule with excluded class."""
        rule = Mock()
        rule.ruletype = TERuletype.allow
        rule.tclass = "infoflow"
        rule.perms = set(["low_r", "med_r", "hi_r", "low_w", "med_w", "hi_w"])

        permmap = PermissionMap("tests/perm_map")
        permmap.exclude_class("infoflow")
        r, w = permmap.rule_weight(rule)
        self.assertEqual(r, 0)
        self.assertEqual(w, 0)

    def test_150_map_policy(self):
        """PermMap create mappings for classes/perms in a policy."""
        permmap = PermissionMap("tests/perm_map")
        permmap.map_policy(self.p)

        self.validate_permmap_entry(permmap.permmap, 'infoflow2', 'new_perm', 'u', 1, True)

        self.assertIn("new_class", permmap.permmap)
        self.assertEqual(1, len(permmap.permmap['new_class']))
        self.validate_permmap_entry(permmap.permmap, 'new_class', 'new_class_perm', 'u', 1, True)
