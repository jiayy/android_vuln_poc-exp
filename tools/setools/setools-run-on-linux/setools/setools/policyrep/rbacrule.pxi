# Copyright 2014, 2016, Tresys Technology, LLC
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

#
# Classes
#
class RBACRuletype(PolicyEnum):

    """An enumeration of RBAC rule types."""

    allow = 1
    role_transition = 2


cdef class RoleAllow(PolicyRule):

    """A role allow rule."""

    @staticmethod
    cdef inline RoleAllow factory(SELinuxPolicy policy, sepol.role_allow_t *symbol):
        """Factory function for creating RoleAllow objects."""
        cdef RoleAllow r = RoleAllow.__new__(RoleAllow)
        r.policy = policy
        r.key = <uintptr_t>symbol
        r.ruletype = RBACRuletype.allow
        r.source = Role.factory(policy, policy.role_value_to_datum(symbol.role - 1))
        r.target = Role.factory(policy, policy.role_value_to_datum(symbol.new_role - 1))
        r.origin = None
        return r

    def __hash__(self):
        return hash("{0.ruletype}|{0.source}|{0.target}".format(self))

    def __lt__(self, other):
        return str(self) < str(other)

    @property
    def tclass(self):
        """The rule's object class."""
        raise RuleUseError("Role allow rules do not have an object class.")

    @property
    def default(self):
        """The rule's default role."""
        raise RuleUseError("Role allow rules do not have a default role.")

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        cdef RoleAllow r
        if self.origin is None:
            for s, t in itertools.product(self.source.expand(), self.target.expand()):
                """Factory function for creating ExpandedRoleAllow objects."""
                r = RoleAllow.__new__(RoleAllow)
                r.policy = self.policy
                r.key = self.key
                r.ruletype = self.ruletype
                r.source = s
                r.target = t
                r.origin = self
                yield r

        else:
            # this rule is already expanded.
            yield self

    def statement(self):
        return "{0.ruletype} {0.source} {0.target};".format(self)


cdef class RoleTransition(PolicyRule):

    """A role_transition rule."""

    cdef:
        readonly ObjClass tclass
        Role dft

    @staticmethod
    cdef inline RoleTransition factory(SELinuxPolicy policy,
                                       sepol.role_trans_t *symbol):
        """Factory function for creating RoleTransition objects."""
        cdef RoleTransition r = RoleTransition.__new__(RoleTransition)
        r.policy = policy
        r.key = <uintptr_t>symbol
        r.ruletype = RBACRuletype.role_transition
        r.source = Role.factory(policy, policy.role_value_to_datum(symbol.role - 1))
        r.target = type_or_attr_factory(policy, policy.type_value_to_datum(symbol.type - 1))
        r.tclass = ObjClass.factory(policy, policy.class_value_to_datum(symbol.tclass - 1))
        r.dft = Role.factory(policy, policy.role_value_to_datum(symbol.new_role - 1))
        r.origin = None

        return r

    def __hash__(self):
        return hash("{0.ruletype}|{0.source}|{0.target}|{0.tclass}|None|None".format(self))

    def __lt__(self, other):
        return str(self) < str(other)

    @property
    def default(self):
        """The rule's default role."""
        return self.dft

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        cdef RoleTransition r
        if self.origin is None:
            for s, t in itertools.product(self.source.expand(), self.target.expand()):
                r = RoleTransition.__new__(RoleTransition)
                r.policy = self.policy
                r.key = self.key
                r.ruletype = self.ruletype
                r.source = s
                r.target = t
                r.tclass = self.tclass
                r.dft = self.dft
                r.origin = self
                yield r

        else:
            # this rule is already expanded.
            yield self

    def statement(self):
        return "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default};".format(self)


#
# Iterators
#
cdef class RoleAllowIterator(PolicyIterator):

    """Role allow rule iterator."""

    cdef:
        sepol.role_allow_t *head
        sepol.role_allow_t *curr

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.role_allow_t *head):
        """Role allow rule iterator factory."""
        i = RoleAllowIterator()
        i.policy = policy
        i.head = head
        i.reset()
        return i

    def __next__(self):
        if self.curr == NULL:
            raise StopIteration

        item = RoleAllow.factory(self.policy, self.curr)
        self.curr = self.curr.next
        return item

    def __len__(self):
        cdef:
            sepol.role_allow_t *curr
            size_t count = 0

        curr = self.head
        while curr != NULL:
             count += 1
             curr = curr.next

        return count

    def reset(self):
        """Reset the iterator back to the start."""
        self.curr = self.head


cdef class RoleTransitionIterator(PolicyIterator):

    """Role transition rule iterator."""

    cdef:
        sepol.role_trans_t *head
        sepol.role_trans_t *curr

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.role_trans_t *head):
        """Role transition rule iterator factory."""
        i = RoleTransitionIterator()
        i.policy = policy
        i.head = head
        i.reset()
        return i

    def __next__(self):
        if self.curr == NULL:
            raise StopIteration

        item = RoleTransition.factory(self.policy, self.curr)
        self.curr = self.curr.next
        return item

    def __len__(self):
        cdef:
            sepol.role_trans_t *curr
            size_t count = 0

        curr = self.head
        while curr != NULL:
             count += 1
             curr = curr.next

        return count

    def reset(self):
        """Reset the iterator back to the start."""
        self.curr = self.head
