# Copyright 2016, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
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

from .descriptors import DiffResultDescriptor
from .difference import Difference, SymbolWrapper, Wrapper

modified_cat_record = namedtuple("modified_category", ["added_aliases",
                                                       "removed_aliases",
                                                       "matched_aliases"])

modified_sens_record = namedtuple("modified_sensitivity", ["added_aliases",
                                                           "removed_aliases",
                                                           "matched_aliases"])

modified_level_record = namedtuple("modified_level", ["level",
                                                      "added_categories",
                                                      "removed_categories",
                                                      "matched_categories"])


_cats_cache = defaultdict(dict)
_sens_cache = defaultdict(dict)


def category_wrapper_factory(category):
    """
    Wrap category from the specified policy.

    This caches results to prevent duplicate wrapper
    objects in memory.
    """
    try:
        return _cats_cache[category.policy][category]
    except KeyError:
        c = SymbolWrapper(category)
        _cats_cache[category.policy][category] = c
        return c


def sensitivity_wrapper_factory(sensitivity):
    """
    Wrap sensitivity from the specified policy.

    This caches results to prevent duplicate wrapper
    objects in memory.
    """
    try:
        return _sens_cache[sensitivity.policy][sensitivity]
    except KeyError:
        c = SymbolWrapper(sensitivity)
        _sens_cache[sensitivity.policy][sensitivity] = c
        return c


class CategoriesDifference(Difference):

    """Determine the difference in categories between two policies."""

    added_categories = DiffResultDescriptor("diff_categories")
    removed_categories = DiffResultDescriptor("diff_categories")
    modified_categories = DiffResultDescriptor("diff_categories")

    def diff_categories(self):
        """Generate the difference in categories between the policies."""

        self.log.info(
            "Generating category differences from {0.left_policy} to {0.right_policy}".format(self))

        self.added_categories, self.removed_categories, matched_categories = self._set_diff(
            (category_wrapper_factory(c) for c in self.left_policy.categories()),
            (category_wrapper_factory(c) for c in self.right_policy.categories()))

        self.modified_categories = dict()

        for left_category, right_category in matched_categories:
            # Criteria for modified categories
            # 1. change to aliases
            added_aliases, removed_aliases, matched_aliases = self._set_diff(
                left_category.aliases(), right_category.aliases(), unwrap=False)

            if added_aliases or removed_aliases:
                self.modified_categories[left_category] = modified_cat_record(added_aliases,
                                                                              removed_aliases,
                                                                              matched_aliases)

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting category differences")
        self.added_categories = None
        self.removed_categories = None
        self.modified_categories = None


class SensitivitiesDifference(Difference):

    """Determine the difference in sensitivities between two policies."""

    added_sensitivities = DiffResultDescriptor("diff_sensitivities")
    removed_sensitivities = DiffResultDescriptor("diff_sensitivities")
    modified_sensitivities = DiffResultDescriptor("diff_sensitivities")

    def diff_sensitivities(self):
        """Generate the difference in sensitivities between the policies."""

        self.log.info(
            "Generating sensitivity differences from {0.left_policy} to {0.right_policy}".
            format(self))

        self.added_sensitivities, self.removed_sensitivities, matched_sensitivities = \
            self._set_diff(
                (sensitivity_wrapper_factory(s) for s in self.left_policy.sensitivities()),
                (sensitivity_wrapper_factory(s) for s in self.right_policy.sensitivities()))

        self.modified_sensitivities = dict()

        for left_sens, right_sens in matched_sensitivities:
            # Criteria for modified sensitivities
            # 1. change to aliases
            added_aliases, removed_aliases, matched_aliases = self._set_diff(
                left_sens.aliases(), right_sens.aliases(), unwrap=False)

            if added_aliases or removed_aliases:
                self.modified_sensitivities[left_sens] = modified_sens_record(added_aliases,
                                                                              removed_aliases,
                                                                              matched_aliases)

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting sensitivity differences")
        self.added_sensitivities = None
        self.removed_sensitivities = None
        self.modified_sensitivities = None


class LevelDeclsDifference(Difference):

    """Determine the difference in levels between two policies."""

    added_levels = DiffResultDescriptor("diff_levels")
    removed_levels = DiffResultDescriptor("diff_levels")
    modified_levels = DiffResultDescriptor("diff_levels")

    def diff_levels(self):
        """Generate the difference in levels between the policies."""

        self.log.info(
            "Generating level decl differences from {0.left_policy} to {0.right_policy}".
            format(self))

        self.added_levels, self.removed_levels, matched_levels = \
            self._set_diff(
                (LevelDeclWrapper(s) for s in self.left_policy.levels()),
                (LevelDeclWrapper(s) for s in self.right_policy.levels()))

        self.modified_levels = []

        for left_level, right_level in matched_levels:
            # Criteria for modified levels
            # 1. change to allowed categories
            added_categories, removed_categories, matched_categories = self._set_diff(
                (category_wrapper_factory(c) for c in left_level.categories()),
                (category_wrapper_factory(c) for c in right_level.categories()))

            if added_categories or removed_categories:
                self.modified_levels.append(modified_level_record(
                    left_level, added_categories, removed_categories, matched_categories))

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting sensitivity differences")
        self.added_levels = None
        self.removed_levels = None
        self.modified_levels = None


class LevelDeclWrapper(Wrapper):

    """Wrap level declarations to allow comparisons."""

    __slots__ = ("sensitivity")

    def __init__(self, level):
        self.origin = level
        self.sensitivity = sensitivity_wrapper_factory(level.sensitivity)
        self.key = hash(level)

    def __hash__(self):
        return self.key

    def __eq__(self, other):
        # non-MLS policies have no level declarations so there
        # should be no AttributeError possiblity here
        return self.sensitivity == other.sensitivity

    def __lt__(self, other):
        return self.sensitivity < other.sensitivity


class LevelWrapper(Wrapper):

    """Wrap levels to allow comparisons."""

    __slots__ = ("sensitivity", "categories")

    def __init__(self, level):
        self.origin = level
        self.sensitivity = sensitivity_wrapper_factory(level.sensitivity)
        self.categories = set(category_wrapper_factory(c) for c in level.categories())

    def __hash__(self):
        raise hash(self.origin)

    def __eq__(self, other):
        try:
            return self.sensitivity == other.sensitivity and \
                self.categories == other.categories
        except AttributeError:
            # comparing an MLS policy to non-MLS policy will result in
            # other being None
            return False

    def __lt__(self, other):
        try:
            return self.sensitivity < other.sensitivity and \
                self.categories < other.categories
        except AttributeError:
            # comparing an MLS policy to non-MLS policy will result in
            # other being None
            return False


class RangeWrapper(Wrapper):

    """
    Wrap ranges to allow comparisons.

    This only compares the low and high levels of the range.
    It does not detect additions/removals/modifications
    to levels between the low and high levels of the range.
    """

    __slots__ = ("low", "high")

    def __init__(self, range_):
        self.origin = range_
        self.low = LevelWrapper(range_.low)
        self.high = LevelWrapper(range_.high)

    def __hash__(self):
        return hash(self.origin)

    def __eq__(self, other):
        try:
            return self.low == other.low and \
                self.high == other.high
        except AttributeError:
            # comparing an MLS policy to non-MLS policy will result in
            # other being None
            return False

    def __lt__(self, other):
        try:
            return self.low < other.low and \
                self.high < other.high
        except AttributeError:
            # comparing an MLS policy to non-MLS policy will result in
            # other being None
            return False
