# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2016-2018, Chris PeBenito <pebenito@ieee.org>
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

cdef class Context(PolicyObject):

    """A SELinux security context/security attribute."""

    cdef:
        readonly User user
        readonly Role role
        readonly Type type_
        Range _range

    @staticmethod
    cdef inline Context factory(SELinuxPolicy policy, sepol.context_struct_t *symbol):
        """Factory function for creating Context objects."""
        cdef Context c = Context.__new__(Context)
        c.policy = policy
        c.key = <uintptr_t>symbol
        c.user = User.factory(policy, policy.user_value_to_datum(symbol.user - 1))
        c.role = Role.factory(policy, policy.role_value_to_datum(symbol.role - 1))
        c.type_ = Type.factory(policy, policy.type_value_to_datum(symbol.type - 1))

        if policy.mls:
            c._range = Range.factory(policy, &symbol.range)

        return c

    def __str__(self):
        if self._range:
            return "{0.user}:{0.role}:{0.type_}:{0.range_}".format(self)
        else:
            return "{0.user}:{0.role}:{0.type_}".format(self)

    @property
    def range_(self):
        """The MLS range of the context."""
        if self._range:
            return self._range
        else:
            raise MLSDisabled

    def statement(self):
        raise NoStatement
