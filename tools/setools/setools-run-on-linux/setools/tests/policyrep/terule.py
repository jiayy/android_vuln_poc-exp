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

from setools import SELinuxPolicy
from setools.exception import InvalidTERuleType, RuleNotConditional, RuleUseError, \
    TERuleNoFilename


@unittest.skip("Needs to be reworked for cython")
@patch('setools.policyrep.boolcond.condexpr_factory', lambda x, y: y)
@patch('setools.policyrep.typeattr.type_or_attr_factory', lambda x, y: y)
@patch('setools.policyrep.objclass.class_factory', lambda x, y: y)
class AVRuleTest(unittest.TestCase):

    def mock_avrule_factory(self, ruletype, source, target, tclass, perms, cond=None):
        mock_rule = Mock(qpol_avrule_t)
        mock_rule.is_extended.return_value = False
        mock_rule.rule_type.return_value = TERuletype.lookup(ruletype)
        mock_rule.source_type.return_value = source
        mock_rule.target_type.return_value = target
        mock_rule.object_class.return_value = tclass
        mock_rule.perm_iter = lambda x: iter(perms)

        if cond:
            mock_rule.cond.return_value = cond
        else:
            # this actually comes out of condexpr_factory
            # but it's simpler to have here
            mock_rule.cond.side_effect = AttributeError

        return te_rule_factory(self.p, mock_rule)

    def setUp(self):
        self.p = Mock(qpol_policy_t)

    def test_000_factory(self):
        """AVRule factory lookup."""
        with self.assertRaises(TypeError):
            te_rule_factory(self.p, "INVALID")

    @unittest.skip("TE ruletype changed to an enumeration.")
    def test_001_validate_ruletype(self):
        """AVRule valid rule types."""
        for r in ["allow", "neverallow", "auditallow", "dontaudit"]:
            self.assertEqual(r, validate_ruletype(r))

    def test_002_validate_ruletype_invalid(self):
        """AVRule valid rule types."""
        with self.assertRaises(InvalidTERuleType):
            self.assertTrue(validate_ruletype("role_transition"))

    def test_010_ruletype(self):
        """AVRule rule type"""
        rule = self.mock_avrule_factory("neverallow", "a", "b", "c", ['d'])
        self.assertEqual(TERuletype.neverallow, rule.ruletype)

    def test_020_source_type(self):
        """AVRule source type"""
        rule = self.mock_avrule_factory("allow", "source20", "b", "c", ['d'])
        self.assertEqual("source20", rule.source)

    def test_030_target_type(self):
        """AVRule target type"""
        rule = self.mock_avrule_factory("allow", "a", "target30", "c", ['d'])
        self.assertEqual("target30", rule.target)

    def test_040_object_class(self):
        """AVRule object class"""
        rule = self.mock_avrule_factory("allow", "a", "b", "class40", ['d'])
        self.assertEqual("class40", rule.tclass)

    def test_050_permissions(self):
        """AVRule permissions"""
        rule = self.mock_avrule_factory("allow", "a", "b", "c", ['perm50a', 'perm50b'])
        self.assertSetEqual(set(['perm50a', 'perm50b']), rule.perms)

    def test_060_conditional(self):
        """AVRule conditional expression"""
        rule = self.mock_avrule_factory("allow", "a", "b", "c", ['d'], cond="cond60")
        self.assertEqual("cond60", rule.conditional)

    def test_061_unconditional(self):
        """AVRule conditional expression (none)"""
        rule = self.mock_avrule_factory("allow", "a", "b", "c", ['d'])
        with self.assertRaises(RuleNotConditional):
            rule.conditional

    def test_070_default(self):
        """AVRule default type"""
        rule = self.mock_avrule_factory("allow", "a", "b", "c", ['d'])
        with self.assertRaises(RuleUseError):
            rule.default

    def test_080_filename(self):
        """AVRule filename (none)"""
        rule = self.mock_avrule_factory("allow", "a", "b", "c", ['d'])
        with self.assertRaises(RuleUseError):
            rule.filename

    def test_100_statement_one_perm(self):
        """AVRule statement, one permission."""
        rule = self.mock_avrule_factory("allow", "a", "b", "c", ['d'])
        self.assertEqual("allow a b:c d;", rule.statement())

    def test_101_statement_two_perms(self):
        """AVRule statement, two permissions."""
        rule = self.mock_avrule_factory("allow", "a", "b", "c", ['d1', 'd2'])

        # permissions are stored in a set, so the order may vary
        self.assertRegex(rule.statement(), "("
                         "allow a b:c { d1 d2 };"
                         "|"
                         "allow a b:c { d2 d1 };"
                         ")")

    def test_102_statement_one_perm_cond(self):
        """AVRule statement, one permission, conditional."""
        rule = self.mock_avrule_factory("allow", "a", "b", "c", ['d'], cond="cond102")
        self.assertEqual("allow a b:c d; [ cond102 ]:True", rule.statement())

    def test_103_statement_two_perms_cond(self):
        """AVRule statement, two permissions, conditional."""
        rule = self.mock_avrule_factory("allow", "a", "b", "c", ['d1', 'd2'], cond="cond103")

        # permissions are stored in a set, so the order may vary
        self.assertRegex(rule.statement(), "("
                         "allow a b:c { d1 d2 }; \[ cond103 ]"
                         "|"
                         "allow a b:c { d2 d1 }; \[ cond103 ]"
                         ")")


@unittest.skip("Needs to be reworked for cython")
@patch('setools.policyrep.boolcond.condexpr_factory', lambda x, y: y)
@patch('setools.policyrep.typeattr.type_or_attr_factory', lambda x, y: y)
@patch('setools.policyrep.objclass.class_factory', lambda x, y: y)
class AVRuleXpermTest(unittest.TestCase):

    def mock_avrule_factory(self, ruletype, source, target, tclass, xperm, perms):
        mock_rule = Mock(qpol_avrule_t)
        mock_rule.is_extended.return_value = True
        mock_rule.rule_type.return_value = TERuletype.lookup(ruletype)
        mock_rule.source_type.return_value = source
        mock_rule.target_type.return_value = target
        mock_rule.object_class.return_value = tclass
        mock_rule.xperm_type.return_value = xperm
        mock_rule.xperm_iter = lambda x: iter(perms)

        # this actually comes out of condexpr_factory
        # but it's simpler to have here
        mock_rule.cond.side_effect = AttributeError

        return te_rule_factory(self.p, mock_rule)

    def setUp(self):
        self.p = Mock(qpol_policy_t)

    def test_000_factory(self):
        """AVRuleXperm factory lookup."""
        with self.assertRaises(TypeError):
            te_rule_factory(self.p, "INVALID")

    @unittest.skip("TE ruletype changed to an enumeration.")
    def test_001_validate_ruletype(self):
        """AVRuleXperm valid rule types."""
        for r in ["allowxperm", "neverallowxperm", "auditallowxperm", "dontauditxperm"]:
            self.assertEqual(r, validate_ruletype(r))

    def test_010_ruletype(self):
        """AVRuleXperm rule type"""
        rule = self.mock_avrule_factory("neverallowxperm", "a", "b", "c", "d", [0x0001])
        self.assertEqual(TERuletype.neverallowxperm, rule.ruletype)

    def test_020_source_type(self):
        """AVRuleXperm source type"""
        rule = self.mock_avrule_factory("allowxperm", "source20", "b", "c", "d", [0x0001])
        self.assertEqual("source20", rule.source)

    def test_030_target_type(self):
        """AVRuleXperm target type"""
        rule = self.mock_avrule_factory("allowxperm", "a", "target30", "c", "d", [0x0001])
        self.assertEqual("target30", rule.target)

    def test_040_object_class(self):
        """AVRuleXperm object class"""
        rule = self.mock_avrule_factory("allowxperm", "a", "b", "class40", "d", [0x0001])
        self.assertEqual("class40", rule.tclass)

    def test_050_permissions(self):
        """AVRuleXperm permissions"""
        rule = self.mock_avrule_factory("allowxperm", "a", "b", "c", "d", [0x0001, 0x0002, 0x0003])
        self.assertSetEqual(set([0x0001, 0x0002, 0x0003]), rule.perms)

    def test_060_xperm_type(self):
        """AVRuleXperm xperm type"""
        rule = self.mock_avrule_factory("allowxperm", "a", "b", "c", "xperm60", [0x0001])
        self.assertEqual("xperm60", rule.xperm_type)

    def test_070_unconditional(self):
        """AVRuleXperm conditional expression (none)"""
        rule = self.mock_avrule_factory("allowxperm", "a", "b", "c", "d", [0x0001])
        with self.assertRaises(RuleNotConditional):
            rule.conditional

    def test_080_default(self):
        """AVRuleXperm default type"""
        rule = self.mock_avrule_factory("allowxperm", "a", "b", "c", "d", [0x0001])
        with self.assertRaises(RuleUseError):
            rule.default

    def test_090_filename(self):
        """AVRuleXperm filename (none)"""
        rule = self.mock_avrule_factory("allowxperm", "a", "b", "c", "d", [0x0001])
        with self.assertRaises(RuleUseError):
            rule.filename

    def test_100_statement_one_perm(self):
        """AVRuleXperm statement, one permission."""
        rule = self.mock_avrule_factory("allowxperm", "a", "b", "c", "d", [0x0001])
        self.assertEqual("allowxperm a b:c d 0x0001;", rule.statement())

    def test_101_statement_two_perms(self):
        """AVRuleXperm statement, two permissions."""
        rule = self.mock_avrule_factory("allowxperm", "a", "b", "c", "d", [0x0001, 0x0003])
        self.assertEqual(rule.statement(), "allowxperm a b:c d { 0x0001 0x0003 };")

    def test_102_statement_range_perms(self):
        """AVRuleXperm statement, range of permissions."""
        rule = self.mock_avrule_factory("allowxperm", "a", "b", "c", "d",
                                        list(range(0x0010, 0x0015)))
        self.assertEqual(rule.statement(), "allowxperm a b:c d 0x0010-0x0014;")

    def test_103_statement_single_perm_range_perms(self):
        """AVRuleXperm statement, single perm with range of permissions."""
        rule = self.mock_avrule_factory("allowxperm", "a", "b", "c", "d",
                                        [0x0001, 0x0003, 0x0004, 0x0005])
        self.assertEqual(rule.statement(), "allowxperm a b:c d { 0x0001 0x0003-0x0005 };")

    def test_104_statement_two_range_perms(self):
        """AVRuleXperm statement, two ranges of permissions."""
        rule = self.mock_avrule_factory("allowxperm", "a", "b", "c", "d",
                                        [0x0003, 0x0004, 0x0005, 0x0007, 0x0008, 0x0009])
        self.assertEqual(rule.statement(), "allowxperm a b:c d { 0x0003-0x0005 0x0007-0x0009 };")


@unittest.skip("Needs to be reworked for cython")
@patch('setools.policyrep.boolcond.condexpr_factory', lambda x, y: y)
@patch('setools.policyrep.typeattr.type_factory', lambda x, y: y)
@patch('setools.policyrep.typeattr.type_or_attr_factory', lambda x, y: y)
@patch('setools.policyrep.objclass.class_factory', lambda x, y: y)
class TERuleTest(unittest.TestCase):

    def mock_terule_factory(self, ruletype, source, target, tclass, default, cond=None,
                            filename=None):

        if filename:
            assert not cond
            mock_rule = Mock(qpol_filename_trans_t)
            mock_rule.filename.return_value = filename

        else:
            mock_rule = Mock(qpol_terule_t)

            if cond:
                mock_rule.cond.return_value = cond
            else:
                # this actually comes out of condexpr_factory
                # but it's simpler to have here
                mock_rule.cond.side_effect = AttributeError

        mock_rule.rule_type.return_value = TERuletype.lookup(ruletype)
        mock_rule.source_type.return_value = source
        mock_rule.target_type.return_value = target
        mock_rule.object_class.return_value = tclass
        mock_rule.default_type.return_value = default

        return te_rule_factory(self.p, mock_rule)

    def setUp(self):
        self.p = Mock(qpol_policy_t)

    def test_000_factory(self):
        """TERule factory lookup."""
        with self.assertRaises(TypeError):
            te_rule_factory(self.p, "INVALID")

    @unittest.skip("TE ruletype changed to an enumeration.")
    def test_001_validate_ruletype(self):
        """TERule valid rule types."""
        for r in ["type_transition", "type_change", "type_member"]:
            self.assertEqual(r, validate_ruletype(r))

    @unittest.skip("TE ruletype changed to an enumeration.")
    def test_002_validate_ruletype_invalid(self):
        """TERule valid rule types."""
        with self.assertRaises(InvalidTERuleType):
            self.assertTrue(validate_ruletype("role_transition"))

    def test_010_ruletype(self):
        """TERule rule type"""
        rule = self.mock_terule_factory("type_transition", "a", "b", "c", "d")
        self.assertEqual(TERuletype.type_transition, rule.ruletype)

    def test_020_source_type(self):
        """TERule source type"""
        rule = self.mock_terule_factory("type_transition", "source20", "b", "c", "d")
        self.assertEqual("source20", rule.source)

    def test_030_target_type(self):
        """TERule target type"""
        rule = self.mock_terule_factory("type_transition", "a", "target30", "c", "d")
        self.assertEqual("target30", rule.target)

    def test_040_object_class(self):
        """TERule object class"""
        rule = self.mock_terule_factory("type_transition", "a", "b", "class40", "d")
        self.assertEqual("class40", rule.tclass)

    def test_050_permissions(self):
        """TERule permissions"""
        rule = self.mock_terule_factory("type_transition", "a", "b", "c", "d")
        with self.assertRaises(RuleUseError):
            rule.perms

    def test_060_conditional(self):
        """TERule conditional expression"""
        rule = self.mock_terule_factory("type_transition", "a", "b", "c", "d", cond="cond60")
        self.assertEqual("cond60", rule.conditional)

    def test_061_unconditional(self):
        """TERule conditional expression (none)"""
        rule = self.mock_terule_factory("type_transition", "a", "b", "c", "d")
        with self.assertRaises(RuleNotConditional):
            rule.conditional

    def test_070_default(self):
        """TERule default type"""
        rule = self.mock_terule_factory("type_transition", "a", "b", "c", "default70")
        self.assertEqual("default70", rule.default)

    def test_080_filename(self):
        """TERule filename"""
        rule = self.mock_terule_factory("type_transition", "a", "b", "c", "d", filename="name80")
        self.assertEqual("name80", rule.filename)

    def test_081_filename_none(self):
        """TERule filename (none)"""
        rule = self.mock_terule_factory("type_transition", "a", "b", "c", "d")
        with self.assertRaises(TERuleNoFilename):
            rule.filename

    def test_082_filename_wrong_ruletype(self):
        """TERule filename on wrong ruletype"""
        rule = self.mock_terule_factory("type_change", "a", "b", "c", "d")
        with self.assertRaises(RuleUseError):
            rule.filename

    def test_100_statement(self):
        """TERule statement."""
        rule1 = self.mock_terule_factory("type_transition", "a", "b", "c", "d")
        rule2 = self.mock_terule_factory("type_change", "a", "b", "c", "d")
        self.assertEqual("type_transition a b:c d;", rule1.statement())
        self.assertEqual("type_change a b:c d;", rule2.statement())

    def test_102_statement_cond(self):
        """TERule statement, conditional."""
        rule = self.mock_terule_factory("type_transition", "a", "b", "c", "d", cond="cond102")
        self.assertEqual("type_transition a b:c d; [ cond102 ]:True", rule.statement())

    def test_103_statement_filename(self):
        """TERule statement, two permissions, conditional."""
        rule = self.mock_terule_factory("type_transition", "a", "b", "c", "d", filename="name103")
        self.assertEqual("type_transition a b:c d \"name103\";", rule.statement())
