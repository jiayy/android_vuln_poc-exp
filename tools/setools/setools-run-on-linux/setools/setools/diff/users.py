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

from ..exception import MLSDisabled

from .descriptors import DiffResultDescriptor
from .difference import Difference, SymbolWrapper
from .mls import LevelWrapper, RangeWrapper
from .roles import role_wrapper_factory


modified_users_record = namedtuple("modified_user", ["added_roles",
                                                     "removed_roles",
                                                     "matched_roles",
                                                     "added_level",
                                                     "removed_level",
                                                     "added_range",
                                                     "removed_range"])

_users_cache = defaultdict(dict)


def user_wrapper_factory(user):
    """
    Wrap users from the specified policy.

    This caches results to prevent duplicate wrapper
    objects in memory.
    """
    try:
        return _users_cache[user.policy][user]
    except KeyError:
        r = SymbolWrapper(user)
        _users_cache[user.policy][user] = r
        return r


class UsersDifference(Difference):

    """Determine the difference in users between two policies."""

    added_users = DiffResultDescriptor("diff_users")
    removed_users = DiffResultDescriptor("diff_users")
    modified_users = DiffResultDescriptor("diff_users")

    def diff_users(self):
        """Generate the difference in users between the policies."""

        self.log.info(
            "Generating user differences from {0.left_policy} to {0.right_policy}".format(self))

        self.added_users, self.removed_users, matched_users = self._set_diff(
            (user_wrapper_factory(r) for r in self.left_policy.users()),
            (user_wrapper_factory(r) for r in self.right_policy.users()))

        self.modified_users = dict()

        for left_user, right_user in matched_users:
            # Criteria for modified users
            # 1. change to role set, or
            # 2. change to default level, or
            # 3. change to range
            added_roles, removed_roles, matched_roles = self._set_diff(
                (role_wrapper_factory(r) for r in left_user.roles),
                (role_wrapper_factory(r) for r in right_user.roles))

            # keep wrapped and unwrapped MLS objects here so there
            # are not several nested try blocks
            try:
                left_level_wrap = LevelWrapper(left_user.mls_level)
                left_range_wrap = RangeWrapper(left_user.mls_range)
                left_level = left_user.mls_level
                left_range = left_user.mls_range
            except MLSDisabled:
                left_level_wrap = None
                left_range_wrap = None
                left_level = "None (MLS Disabled)"
                left_range = "None (MLS Disabled)"

            try:
                right_level_wrap = LevelWrapper(right_user.mls_level)
                right_range_wrap = RangeWrapper(right_user.mls_range)
                right_level = right_user.mls_level
                right_range = right_user.mls_range
            except MLSDisabled:
                right_level_wrap = None
                right_range_wrap = None
                right_level = "None (MLS Disabled)"
                right_range = "None (MLS Disabled)"

            if left_level_wrap != right_level_wrap:
                added_level = right_level
                removed_level = left_level
            else:
                added_level = None
                removed_level = None

            if left_range_wrap != right_range_wrap:
                added_range = right_range
                removed_range = left_range
            else:
                added_range = None
                removed_range = None

            if added_roles or removed_roles or removed_level or removed_range:
                self.modified_users[left_user] = modified_users_record(added_roles,
                                                                       removed_roles,
                                                                       matched_roles,
                                                                       added_level,
                                                                       removed_level,
                                                                       added_range,
                                                                       removed_range)

    #
    # Internal functions
    #
    def _reset_diff(self):
        """Reset diff results on policy changes."""
        self.log.debug("Resetting user differences")
        self.added_users = None
        self.removed_users = None
        self.modified_users = None
