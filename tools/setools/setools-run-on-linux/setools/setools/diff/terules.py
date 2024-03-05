# Copyright 2015-2016, Tresys Technology, LLC
# Copyright 2016, 2018, Chris PeBenito <pebenito@ieee.org>
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#
from collections import defaultdict, namedtuple

from ..exception import RuleNotConditional, RuleUseError, TERuleNoFilename
from ..policyrep import IoctlSet, TERuletype

from .conditional import conditional_wrapper_factory
from .descriptors import DiffResultDescriptor
from .difference import Difference, Wrapper
from .types import type_wrapper_factory, type_or_attr_wrapper_factory
from .objclass import class_wrapper_factory


modified_avrule_record = namedtuple("modified_avrule", ["rule",
                                                        "added_perms",
                                                        "removed_perms",
                                                        "matched_perms"])

modified_terule_record = namedtuple("modified_terule", ["rule", "added_default", "removed_default"])


def _avrule_expand_generator(rule_list, WrapperClass):
    """
    Generator that yields wrapped, expanded, av(x) rules with
    unioned permission sets.
    """
    items = dict()

    for unexpanded_rule in rule_list:
        for expanded_rule in unexpanded_rule.expand():
            expanded_wrapped_rule = WrapperClass(expanded_rule)

            # create a hash table (dict) with the first rule
            # as the key and value.  Rules where permission sets should
            # be unioned together have the same hash, so this will union
            # the permissions together.
            try:
                items[expanded_wrapped_rule].perms |= expanded_wrapped_rule.perms
            except KeyError:
                items[expanded_wrapped_rule] = expanded_wrapped_rule

    return items.keys()


def av_diff_template(ruletype):

    """
    This is a template for the access vector diff functions.

    Parameters:
    ruletype    The rule type, e.g. "allow".
    """
    ruletype = TERuletype.lookup(ruletype)

    def diff(self):
        """Generate the difference in rules between the policies."""

        self.log.info(
            "Generating {0} differences from {1.left_policy} to {1.right_policy}".
            format(ruletype, self))

        if not self._left_te_rules or not self._right_te_rules:
            self._create_te_rule_lists()

        added, removed, matched = self._set_diff(
            _avrule_expand_generator(self._left_te_rules[ruletype], AVRuleWrapper),
            _avrule_expand_generator(self._right_te_rules[ruletype], AVRuleWrapper),
            unwrap=False)

        modified = []
        for left_rule, right_rule in matched:
            # Criteria for modified rules
            # 1. change to permissions
            added_perms, removed_perms, matched_perms = self._set_diff(left_rule.perms,
                                                                       right_rule.perms,
                                                                       unwrap=False)

            # the final set comprehension is to avoid having lists
            # like [("perm1", "perm1"), ("perm2", "perm2")], as the
            # matched_perms return from _set_diff is a set of tuples
            if added_perms or removed_perms:
                modified.append(modified_avrule_record(left_rule.origin,
                                                       added_perms,
                                                       removed_perms,
                                                       set(p[0] for p in matched_perms)))

        setattr(self, "added_{0}s".format(ruletype), set(a.origin for a in added))
        setattr(self, "removed_{0}s".format(ruletype), set(r.origin for r in removed))
        setattr(self, "modified_{0}s".format(ruletype), modified)

    return diff


def avx_diff_template(ruletype):

    """
    This is a template for the extended permission access vector diff functions.

    Parameters:
    ruletype    The rule type, e.g. "allowxperm".
    """
    ruletype = TERuletype.lookup(ruletype)

    def diff(self):
        """Generate the difference in rules between the policies."""

        self.log.info(
            "Generating {0} differences from {1.left_policy} to {1.right_policy}".
            format(ruletype, self))

        if not self._left_te_rules or not self._right_te_rules:
            self._create_te_rule_lists()

        added, removed, matched = self._set_diff(
            _avrule_expand_generator(self._left_te_rules[ruletype], AVRuleXpermWrapper),
            _avrule_expand_generator(self._right_te_rules[ruletype], AVRuleXpermWrapper),
            unwrap=False)

        modified = []
        for left_rule, right_rule in matched:
            # Criteria for modified rules
            # 1. change to permissions
            added_perms, removed_perms, matched_perms = self._set_diff(left_rule.perms,
                                                                       right_rule.perms,
                                                                       unwrap=False)

            # the final set comprehension is to avoid having lists
            # like [("perm1", "perm1"), ("perm2", "perm2")], as the
            # matched_perms return from _set_diff is a set of tuples
            if added_perms or removed_perms:
                modified.append(modified_avrule_record(left_rule.origin,
                                                       IoctlSet(added_perms),
                                                       IoctlSet(removed_perms),
                                                       IoctlSet(p[0] for p in matched_perms)))

        setattr(self, "added_{0}s".format(ruletype), set(a.origin for a in added))
        setattr(self, "removed_{0}s".format(ruletype), set(r.origin for r in removed))
        setattr(self, "modified_{0}s".format(ruletype), modified)

    return diff


def te_diff_template(ruletype):

    """
    This is a template for the type_* diff functions.

    Parameters:
    ruletype    The rule type, e.g. "type_transition".
    """
    ruletype = TERuletype.lookup(ruletype)

    def diff(self):
        """Generate the difference in rules between the policies."""

        self.log.info(
            "Generating {0} differences from {1.left_policy} to {1.right_policy}".
            format(ruletype, self))

        if not self._left_te_rules or not self._right_te_rules:
            self._create_te_rule_lists()

        added, removed, matched = self._set_diff(
            self._expand_generator(self._left_te_rules[ruletype], TERuleWrapper),
            self._expand_generator(self._right_te_rules[ruletype], TERuleWrapper))

        modified = []
        for left_rule, right_rule in matched:
            # Criteria for modified rules
            # 1. change to default type
            if type_wrapper_factory(left_rule.default) != type_wrapper_factory(right_rule.default):
                modified.append(modified_terule_record(left_rule,
                                                       right_rule.default,
                                                       left_rule.default))

        setattr(self, "added_{0}s".format(ruletype), added)
        setattr(self, "removed_{0}s".format(ruletype), removed)
        setattr(self, "modified_{0}s".format(ruletype), modified)

    return diff


class TERulesDifference(Difference):

    """
    Determine the difference in type enforcement rules
    between two policies.
    """

    diff_allows = av_diff_template("allow")
    added_allows = DiffResultDescriptor("diff_allows")
    removed_allows = DiffResultDescriptor("diff_allows")
    modified_allows = DiffResultDescriptor("diff_allows")

    diff_auditallows = av_diff_template("auditallow")
    added_auditallows = DiffResultDescriptor("diff_auditallows")
    removed_auditallows = DiffResultDescriptor("diff_auditallows")
    modified_auditallows = DiffResultDescriptor("diff_auditallows")

    diff_neverallows = av_diff_template("neverallow")
    added_neverallows = DiffResultDescriptor("diff_neverallows")
    removed_neverallows = DiffResultDescriptor("diff_neverallows")
    modified_neverallows = DiffResultDescriptor("diff_neverallows")

    diff_dontaudits = av_diff_template("dontaudit")
    added_dontaudits = DiffResultDescriptor("diff_dontaudits")
    removed_dontaudits = DiffResultDescriptor("diff_dontaudits")
    modified_dontaudits = DiffResultDescriptor("diff_dontaudits")

    diff_allowxperms = avx_diff_template("allowxperm")
    added_allowxperms = DiffResultDescriptor("diff_allowxperms")
    removed_allowxperms = DiffResultDescriptor("diff_allowxperms")
    modified_allowxperms = DiffResultDescriptor("diff_allowxperms")

    diff_auditallowxperms = avx_diff_template("auditallowxperm")
    added_auditallowxperms = DiffResultDescriptor("diff_auditallowxperms")
    removed_auditallowxperms = DiffResultDescriptor("diff_auditallowxperms")
    modified_auditallowxperms = DiffResultDescriptor("diff_auditallowxperms")

    diff_neverallowxperms = avx_diff_template("neverallowxperm")
    added_neverallowxperms = DiffResultDescriptor("diff_neverallowxperms")
    removed_neverallowxperms = DiffResultDescriptor("diff_neverallowxperms")
    modified_neverallowxperms = DiffResultDescriptor("diff_neverallowxperms")

    diff_dontauditxperms = avx_diff_template("dontauditxperm")
    added_dontauditxperms = DiffResultDescriptor("diff_dontauditxperms")
    removed_dontauditxperms = DiffResultDescriptor("diff_dontauditxperms")
    modified_dontauditxperms = DiffResultDescriptor("diff_dontauditxperms")

    diff_type_transitions = te_diff_template("type_transition")
    added_type_transitions = DiffResultDescriptor("diff_type_transitions")
    removed_type_transitions = DiffResultDescriptor("diff_type_transitions")
    modified_type_transitions = DiffResultDescriptor("diff_type_transitions")

    diff_type_changes = te_diff_template("type_change")
    added_type_changes = DiffResultDescriptor("diff_type_changes")
    removed_type_changes = DiffResultDescriptor("diff_type_changes")
    modified_type_changes = DiffResultDescriptor("diff_type_changes")

    diff_type_members = te_diff_template("type_member")
    added_type_members = DiffResultDescriptor("diff_type_members")
    removed_type_members = DiffResultDescriptor("diff_type_members")
    modified_type_members = DiffResultDescriptor("diff_type_members")

    # Lists of rules for each policy
    _left_te_rules = defaultdict(list)
    _right_te_rules = defaultdict(list)

    #
    # Internal functions
    #
    def _create_te_rule_lists(self):
        """Create rule lists for both policies."""
        # do not expand yet, to keep memory
        # use down as long as possible
        self.log.debug("Building TE rule lists from {0.left_policy}".format(self))
        for rule in self.left_policy.terules():
            self._left_te_rules[rule.ruletype].append(rule)

        self.log.debug("Building TE rule lists from {0.right_policy}".format(self))
        for rule in self.right_policy.terules():
            self._right_te_rules[rule.ruletype].append(rule)

        self.log.debug("Completed building TE rule lists.")

    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting TE rule differences")
        self.added_allows = None
        self.removed_allows = None
        self.modified_allows = None
        self.added_auditallows = None
        self.removed_auditallows = None
        self.modified_auditallows = None
        self.added_neverallows = None
        self.removed_neverallows = None
        self.modified_neverallows = None
        self.added_dontaudits = None
        self.removed_dontaudits = None
        self.modified_dontaudits = None
        self.added_allowxperms = None
        self.removed_allowxperms = None
        self.modified_allowxperms = None
        self.added_auditallowxperms = None
        self.removed_auditallowxperms = None
        self.modified_auditallowxperms = None
        self.added_neverallowxperms = None
        self.removed_neverallowxperms = None
        self.modified_neverallowxperms = None
        self.added_dontauditxperms = None
        self.removed_dontauditxperms = None
        self.modified_dontauditxperms = None
        self.added_type_transitions = None
        self.removed_type_transitions = None
        self.modified_type_transitions = None
        self.added_type_changes = None
        self.removed_type_changes = None
        self.modified_type_changes = None
        self.added_type_members = None
        self.removed_type_members = None
        self.modified_type_members = None

        # Sets of rules for each policy
        self._left_te_rules.clear()
        self._right_te_rules.clear()


class AVRuleWrapper(Wrapper):

    """Wrap access vector rules to allow set operations."""

    __slots__ = ("source", "target", "tclass", "perms", "conditional", "conditional_block")

    def __init__(self, rule):
        self.origin = rule
        self.source = type_or_attr_wrapper_factory(rule.source)
        self.target = type_or_attr_wrapper_factory(rule.target)
        self.tclass = class_wrapper_factory(rule.tclass)
        self.perms = rule.perms
        self.key = hash(rule)

        try:
            self.conditional = conditional_wrapper_factory(rule.conditional)
            self.conditional_block = rule.conditional_block
        except RuleNotConditional:
            self.conditional = None
            self.conditional_block = None

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        # because TERuleDifference groups rules by ruletype,
        # the ruletype always matches.
        return self.source == other.source and \
            self.target == other.target and \
            self.tclass == other.tclass and \
            self.conditional == other.conditional and \
            self.conditional_block == other.conditional_block


class AVRuleXpermWrapper(Wrapper):

    """Wrap extended permission access vector rules to allow set operations."""

    __slots__ = ("source", "target", "tclass", "xperm_type", "perms")

    def __init__(self, rule):
        self.origin = rule
        self.source = type_or_attr_wrapper_factory(rule.source)
        self.target = type_or_attr_wrapper_factory(rule.target)
        self.tclass = class_wrapper_factory(rule.tclass)
        self.xperm_type = rule.xperm_type
        self.perms = rule.perms
        self.key = hash(rule)

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        # because TERuleDifference groups rules by ruletype,
        # the ruletype always matches.
        return self.source == other.source and \
            self.target == other.target and \
            self.tclass == other.tclass and \
            self.xperm_type == other.xperm_type


class TERuleWrapper(Wrapper):

    """Wrap type_* rules to allow set operations."""

    __slots__ = ("source", "target", "tclass", "conditional", "conditional_block", "filename")

    def __init__(self, rule):
        self.origin = rule
        self.source = type_or_attr_wrapper_factory(rule.source)
        self.target = type_or_attr_wrapper_factory(rule.target)
        self.tclass = class_wrapper_factory(rule.tclass)
        self.key = hash(rule)

        try:
            self.conditional = conditional_wrapper_factory(rule.conditional)
            self.conditional_block = rule.conditional_block
        except RuleNotConditional:
            self.conditional = None
            self.conditional_block = None

        try:
            self.filename = rule.filename
        except (RuleUseError, TERuleNoFilename):
            self.filename = None

    def __hash__(self):
        return self.key

    def __lt__(self, other):
        return self.key < other.key

    def __eq__(self, other):
        # because TERuleDifference groups rules by ruletype,
        # the ruletype always matches.
        return self.source == other.source and \
            self.target == other.target and \
            self.tclass == other.tclass and \
            self.conditional == other.conditional and \
            self.conditional_block == other.conditional_block and \
            self.filename == self.filename
