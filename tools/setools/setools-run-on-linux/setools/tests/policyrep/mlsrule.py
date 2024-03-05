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
from unittest.mock import Mock, patch

from setools import MLSRuletype as MRT
from setools.exception import InvalidMLSRuleType, RuleNotConditional


@unittest.skip("Needs to be reworked for cython")
@patch('setools.policyrep.mls.range_factory', lambda x, y: y)
@patch('setools.policyrep.typeattr.type_or_attr_factory', lambda x, y: y)
@patch('setools.policyrep.objclass.class_factory', lambda x, y: y)
class MLSRuleTest(unittest.TestCase):

    def mock_rangetrans_factory(self, source, target, tclass, default):
        mock_rule = Mock(qpol_range_trans_t)
        mock_rule.rule_type.return_value = MRT.range_transition
        mock_rule.source_type.return_value = source
        mock_rule.target_type.return_value = target
        mock_rule.object_class.return_value = tclass
        mock_rule.range.return_value = default

        return mls_rule_factory(self.p, mock_rule)

    def setUp(self):
        self.p = Mock(qpol_policy_t)

    def test_000_factory(self):
        """RangeTransition factory lookup."""
        with self.assertRaises(TypeError):
            mls_rule_factory(self.p, "INVALID")

    def test_001_validate_ruletype(self):
        """RangeTransition valid rule types."""
        self.assertEqual(MRT.range_transition, validate_ruletype("range_transition"))

    @unittest.skip("MLS ruletype changed to an enumeration.")
    def test_002_validate_ruletype_invalid(self):
        """RangeTransition valid rule types."""
        with self.assertRaises(InvalidMLSRuleType):
            self.assertTrue(validate_ruletype("type_transition"))

    def test_010_ruletype(self):
        """RangeTransition rule type"""
        rule = self.mock_rangetrans_factory("a", "b", "c", "d")
        self.assertEqual(MRT.range_transition, rule.ruletype)

    def test_020_source_type(self):
        """RangeTransition source type"""
        rule = self.mock_rangetrans_factory("source20", "b", "c", "d")
        self.assertEqual("source20", rule.source)

    def test_030_target_type(self):
        """RangeTransition target type"""
        rule = self.mock_rangetrans_factory("a", "target30", "c", "d")
        self.assertEqual("target30", rule.target)

    def test_040_object_class(self):
        """RangeTransition object class"""
        rule = self.mock_rangetrans_factory("a", "b", "class40", "d")
        self.assertEqual("class40", rule.tclass)

    def test_050_default(self):
        """RangeTransition default range"""
        rule = self.mock_rangetrans_factory("a", "b", "c", "default50")
        self.assertEqual("default50", rule.default)

    def test_060_conditional(self):
        """RangeTransition conditional expression"""
        rule = self.mock_rangetrans_factory("a", "b", "c", "d")
        with self.assertRaises(RuleNotConditional):
            rule.conditional

    def test_100_statement(self):
        """RangeTransition statement."""
        rule = self.mock_rangetrans_factory("a", "b", "c", "d")
        self.assertEqual("range_transition a b:c d;", rule.statement())
