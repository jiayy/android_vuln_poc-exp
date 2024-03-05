# Copyright 2014-2015, Tresys Technology, LLC
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


cdef class PolicyCapability(PolicySymbol):

    """A policy capability."""

    @staticmethod
    cdef inline PolicyCapability factory(SELinuxPolicy policy, size_t bit):
        """Factory function for creating PolicyCapability objects."""
        cdef PolicyCapability r = PolicyCapability.__new__(PolicyCapability)
        r.policy = policy
        r.name = intern(sepol.sepol_polcap_getname(bit))
        return r

    def __eq__(self, other):
        try:
            return self.policy == other.policy \
                and self.name == other.name
        except AttributeError:
            return self.name == str(other)

    def __hash__(self):
        return hash(self.name)

    def statement(self):
        return "policycap {0};".format(self)


cdef class PolicyCapabilityIterator(EbitmapIterator):

    """Iterator for policy capability statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ebitmap_t *bmap):
        """Factory function for creating PolicyCapability iterators."""
        i = PolicyCapabilityIterator()
        i.policy = policy
        i.bmap = bmap
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return PolicyCapability.factory(self.policy, self.bit)
