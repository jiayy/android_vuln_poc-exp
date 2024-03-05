# Copyright 2014, Tresys Technology, LLC
# Copyright 2017-2018, Chris PeBenito <pebenito@ieee.org>
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


cdef class Role(PolicySymbol):

    """A role."""

    cdef frozenset _types

    @staticmethod
    cdef inline Role factory(SELinuxPolicy policy, sepol.role_datum_t *symbol):
        """Factory function for creating Role objects."""
        cdef Role r = Role.__new__(Role)
        r.policy = policy
        r.key = <uintptr_t>symbol
        r.name = policy.role_value_to_name(symbol.s.value - 1)
        r._types = frozenset(TypeEbitmapIterator.factory_from_set(policy, &symbol.types))
        return r

    @property
    def dominated_roles(self):
        """The roles that this role dominates."""
        # TODO: do dominated roles even work?
        #return set(RoleEbitmapIterator.factory(self.policy, &self.handle.dominates))
        return frozenset()

    def expand(self):
        """Generator that expands this into its member roles."""
        yield self

    def types(self):
        """Generator which yields the role's set of types."""
        return iter(self._types)

    def statement(self):
        cdef size_t count
        types = list(str(t) for t in self._types)
        count = len(types)
        stmt = "role {0}".format(self)
        if count == 1:
            stmt += " types {0}".format(types[0])
        else:
            stmt += " types {{ {0} }}".format(' '.join(types))

        stmt += ";"
        return stmt


#
# Iterator Classes
#
cdef class RoleHashtabIterator(HashtabIterator):

    """Iterate over roles in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating Role iterators."""
        i = RoleHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return Role.factory(self.policy, <sepol.role_datum_t *>self.curr.datum)


cdef class RoleEbitmapIterator(EbitmapIterator):

    """Iterate over a role ebitmap."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ebitmap_t *bmap):
        """Factory function for creating Role ebitmap iterators."""
        i = RoleEbitmapIterator()
        i.policy = policy
        i.bmap = bmap
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return Role.factory(self.policy, self.policy.role_value_to_datum(self.bit))
