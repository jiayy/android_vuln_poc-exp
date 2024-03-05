"""Unit test mixin classes."""
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
# pylint: disable=too-few-public-methods
import unittest

from setools.exception import RuleNotConditional, RuleUseError


class ValidateRule(unittest.TestCase):

    """Mixin for validating policy rules."""

    def validate_rule(self, rule, ruletype, source, target, tclass, last_item, cond=None,
                      cond_block=None, xperm=None):
        """Validate a rule."""
        self.assertEqual(ruletype, rule.ruletype)
        self.assertEqual(source, rule.source)
        self.assertEqual(target, rule.target)
        self.assertEqual(tclass, rule.tclass)

        try:
            # This is the common case.
            self.assertSetEqual(last_item, rule.perms)
        except (AttributeError, RuleUseError):
            self.assertEqual(last_item, rule.default)

        if cond:
            self.assertEqual(cond, rule.conditional)
        else:
            self.assertRaises(RuleNotConditional, getattr, rule, "conditional")

        if cond_block is not None:
            self.assertEqual(cond_block, rule.conditional_block)

        if xperm:
            self.assertEqual(xperm, rule.xperm_type)
            self.assertTrue(rule.extended)
        else:
            self.assertRaises(AttributeError, getattr, rule, "xperm_type")
            self.assertFalse(rule.extended)
