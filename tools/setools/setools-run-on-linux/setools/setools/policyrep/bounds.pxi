# Copyright 2016, Tresys Technology, LLC
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
class BoundsRuletype(PolicyEnum):

    """Enumeration of *bounds rule types."""

    typebounds = 1


cdef class Bounds(PolicyObject):

    """A bounds statement."""

    cdef:
        readonly object ruletype
        readonly object parent
        readonly object child

    @staticmethod
    cdef inline Bounds factory(SELinuxPolicy policy, parent, child):
        """Factory function for creating Bounds objects."""
        cdef Bounds b = Bounds.__new__(Bounds)
        b.policy = policy
        b.ruletype = BoundsRuletype.typebounds
        b.parent = parent
        b.child = child
        return b

    def __hash__(self):
        return hash("{0.ruletype}|{0.child};".format(self))

    def __eq__(self, other):
        return self.policy == other.policy \
            and self.ruletype == other.ruletype \
            and self.parent == other.parent \
            and self.child == other.child

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    def statement(self):
        return "{0.ruletype} {0.parent} {0.child};".format(self)


#
# Iterators
#
cdef class TypeboundsIterator(HashtabIterator):

    """Iterate over typebounds rules in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating typebounds iterators."""
        i = TypeboundsIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        cdef sepol.type_datum_t *datum
        super().__next__()

        datum = <sepol.type_datum_t *> self.curr.datum
        while datum.flavor != sepol.TYPE_TYPE or datum.bounds == 0:
            super().__next__()
            datum = <sepol.type_datum_t *> self.curr.datum

        return Bounds.factory(self.policy,
            Type.factory(self.policy, self.policy.type_value_to_datum(datum.bounds - 1)),
            Type.factory(self.policy, datum))

    def __len__(self):
        cdef:
            sepol.type_datum_t *datum
            sepol.hashtab_node_t *node
            uint32_t bucket = 0
            size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.type_datum_t *>node.datum if node else NULL
                if datum != NULL and datum.flavor == sepol.TYPE_TYPE and datum.bounds != 0:
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        cdef sepol.type_datum_t * datum

        super().reset()

        # advance over any attributes or aliases
        datum = <sepol.type_datum_t *> self.node.datum
        while datum != NULL and datum.flavor != sepol.TYPE_TYPE and datum.bounds == 0:
            self._next_node()
            datum = <sepol.type_datum_t *> self.node.datum
