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

cdef object _common_cache = WeakKeyDefaultDict(dict)
cdef object _objclass_cache = WeakKeyDefaultDict(dict)


#
# Classes
#
cdef class Common(PolicySymbol):

    """A common permission set."""

    cdef:
        dict _perm_table
        readonly frozenset perms

    @staticmethod
    cdef inline Common factory(SELinuxPolicy policy, sepol.common_datum_t *symbol):
        """Factory function for creating Common objects."""
        cdef:
            Common c
            sepol.hashtab_node_t *node
            uint32_t bucket = 0
            str key
            uint32_t value
            dict perm_table

        try:
            return _common_cache[policy][<uintptr_t>symbol]
        except KeyError:
            c = Common.__new__(Common)
            c.policy = policy
            c.key = <uintptr_t>symbol
            c.name = policy.common_value_to_name(symbol.s.value - 1)

            #
            # Create value:name permission table (reverse of what is in the policydb)
            #
            c._perm_table = {}
            while bucket < symbol.permissions.table[0].size:
                node = symbol.permissions.table[0].htable[bucket]
                while node != NULL:
                    key = intern(<char *>node.key)
                    value = (<sepol.perm_datum_t *>node.datum).s.value
                    c._perm_table[value] = key
                    node = node.next

                bucket += 1

            c.perms = frozenset(c._perm_table.values())

            _common_cache[policy][<uintptr_t>symbol] = c
            return c

    def __contains__(self, other):
        return other in self.perms

    def statement(self):
        return "common {0}\n{{\n\t{1}\n}}".format(self, '\n\t'.join(self.perms))


cdef class ObjClass(PolicySymbol):

    """An object class."""

    cdef:
        Common _common
        dict _perm_table
        list _defaults
        list _constraints
        list _validatetrans
        readonly frozenset perms
        # class_datum_t->permissions.nprim
        # is needed for the permission iterator
        uint32_t nprim

    @staticmethod
    cdef inline ObjClass factory(SELinuxPolicy policy, sepol.class_datum_t *symbol):
        """Factory function for creating ObjClass objects."""
        cdef:
            sepol.hashtab_node_t *node
            uint32_t bucket = 0
            str key
            uint32_t value
            dict perm_table
            object com
            ObjClass c

        try:
            return _objclass_cache[policy][<uintptr_t>symbol]
        except KeyError:
            #
            # Instantiate object class
            #
            c = ObjClass.__new__(ObjClass)
            _objclass_cache[policy][<uintptr_t>symbol] = c
            c.policy = policy
            c.key = <uintptr_t>symbol
            c.nprim = symbol.permissions.nprim
            c.name = policy.class_value_to_name(symbol.s.value - 1)

            #
            # Load common
            #
            if symbol.comdatum:
                c._common = Common.factory(policy, symbol.comdatum)

            c._perm_table = {}

            #
            # Create value:name permission table (reverse of what is in the policydb)
            #
            while bucket < symbol.permissions.table[0].size:
                node = symbol.permissions.table[0].htable[bucket]
                while node != NULL:
                    key = intern(<char *>node.key)
                    value = (<sepol.perm_datum_t *>node.datum).s.value
                    c._perm_table[value] = key
                    node = node.next

                bucket += 1

            c.perms = frozenset(c._perm_table.values())

            #
            # Load defaults
            #
            c._defaults = []
            if symbol.default_user:
                c._defaults.append(Default.factory(policy, c, symbol.default_user, None, None, None))

            if symbol.default_role:
                c._defaults.append(Default.factory(policy, c, None, symbol.default_role, None, None))

            if symbol.default_type:
                c._defaults.append(Default.factory(policy, c, None, None, symbol.default_type, None))

            if symbol.default_range:
                c._defaults.append(Default.factory(policy, c, None, None, None, symbol.default_range))

            return c

    def __contains__(self, other):
        try:
            if other in self.common.perms:
                return True
        except NoCommon:
            pass

        return other in self.perms

    @property
    def common(self):
        """
        The common that the object class inherits.

        Exceptions:
        NoCommon    The object class does not inherit a common.
        """
        if self._common:
            return self._common
        else:
            raise NoCommon("{0} does not inherit a common.".format(self.name))

    def constraints(self):
        """Iterator for the constraints that apply to this class."""
        cdef sepol.class_datum_t *symbol = <sepol.class_datum_t *>self.key
        if self._constraints is None:
            self._constraints = list(ConstraintIterator.factory(self.policy, self,
                                                                symbol.constraints))

        return iter(self._constraints)

    def defaults(self):
        """Iterator for the defaults for this object class."""
        return iter(self._defaults)

    def statement(self):
        stmt = "class {0}\n".format(self.name)

        try:
            stmt += "inherits {0}\n".format(self.common)
        except NoCommon:
            pass

        # a class that inherits may not have additional permissions
        if len(self.perms) > 0:
            stmt += "{{\n\t{0}\n}}".format('\n\t'.join(self.perms))

        return stmt

    def validatetrans(self):
        """Iterator for validatetrans that apply to this class."""
        cdef sepol.class_datum_t *symbol = <sepol.class_datum_t *>self.key
        if self._validatetrans is None:
            self._validatetrans = list(ValidatetransIterator.factory(self.policy, self,
                                                                     symbol.validatetrans))

        return iter(self._validatetrans)

#
# Iterators
#
cdef class CommonHashtabIterator(HashtabIterator):

    """Iterate over commons in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating Role iterators."""
        i = CommonHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return Common.factory(self.policy, <sepol.common_datum_t *>self.curr.datum)


cdef class ObjClassHashtabIterator(HashtabIterator):

    """Iterate over roles in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating Role iterators."""
        i = ObjClassHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return ObjClass.factory(self.policy, <sepol.class_datum_t *>self.curr.datum)


cdef class PermissionVectorIterator(PolicyIterator):

    """Iterate over an access (permission) vector"""

    cdef:
        uint32_t vector
        uint32_t curr
        uint32_t perm_max
        dict perm_table

    @staticmethod
    cdef factory(SELinuxPolicy policy, ObjClass tclass, uint32_t vector):
        """Factory method for access vectors."""
        cdef Common com
        i = PermissionVectorIterator()
        i.policy = policy
        i.vector = vector
        i.perm_max = tclass.nprim

        i.perm_table = tclass._perm_table.copy()
        try:
            com = tclass.common
            i.perm_table.update(com._perm_table)
        except NoCommon:
            pass

        i.reset()
        return i

    def __next__(self):
        cdef str name

        if not self.curr < self.perm_max:
            raise StopIteration

        name = self.perm_table[self.curr + 1]

        self.curr += 1
        while self.curr < self.perm_max and not self.vector & (1 << self.curr):
            self.curr += 1

        return name

    def __len__(self):
        cdef:
            uint32_t count = 0
            uint32_t curr = 0

        while curr < self.perm_max:
            if self.vector & (1 << curr):
                count += 1

    def reset(self):
        """Reset the iterator back to the start."""
        self.curr = 0
        while self.curr < self.perm_max and not self.vector & (1 << self.curr):
            self.curr += 1
