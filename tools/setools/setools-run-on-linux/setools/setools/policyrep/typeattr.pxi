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

#
# Cache objects
#
cdef object _type_cache = WeakKeyDefaultDict(dict)
cdef object _typeattr_cache = WeakKeyDefaultDict(dict)


#
# Type or attribute factory function
#
cdef inline BaseType type_or_attr_factory(SELinuxPolicy policy, sepol.type_datum_t *symbol):
    """Factory function for creating type or attribute objects."""
    if symbol.flavor == sepol.TYPE_ATTRIB:
        return TypeAttribute.factory(policy, symbol)
    else:
        return Type.factory(policy, symbol)


#
# Classes
#
cdef class BaseType(PolicySymbol):

    """Type/attribute base class."""

    def expand(self):
        """Generator that expands this attribute into its member types."""
        raise NotImplementedError

    def attributes(self):
        """Generator that yields all attributes for this type."""
        raise NotImplementedError

    def aliases(self):
        """Generator that yields all aliases for this type."""
        raise NotImplementedError


cdef class Type(BaseType):

    """A type."""

    cdef:
        readonly object ispermissive
        list _aliases
        list _attrs
        # type_datum_t.s.value is needed by the
        # alias iterator
        uint32_t value

    @staticmethod
    cdef inline Type factory(SELinuxPolicy policy, sepol.type_datum_t *symbol):
        """Factory function for creating Type objects."""
        cdef Type t
        if symbol.flavor != sepol.TYPE_TYPE:
            raise ValueError("{0} is not a type".format(
                policy.type_value_to_name(symbol.s.value - 1)))

        try:
            return _type_cache[policy][<uintptr_t>symbol]
        except KeyError:
            t = Type.__new__(Type)
            _type_cache[policy][<uintptr_t>symbol] = t
            t.policy = policy
            t.key = <uintptr_t>symbol
            t.value = symbol.s.value
            t.name = policy.type_value_to_name(symbol.s.value - 1)
            t.ispermissive = <bint>symbol.flags & sepol.TYPE_FLAGS_PERMISSIVE
            return t

    cdef inline void _load_aliases(self):
        """Helper method to load aliases."""
        if self._aliases is None:
            self._aliases = list(self.policy.type_aliases(self))

    cdef inline void _load_attributes(self):
        """Helper method to load attributes."""
        cdef sepol.type_datum_t *symbol = <sepol.type_datum_t *>self.key
        if self._attrs is None:
            self._attrs = list(TypeAttributeEbitmapIterator.factory(self.policy, &symbol.types))

    def expand(self):
        """Generator that expands this into its member types."""
        yield self

    def attributes(self):
        """Generator that yields all attributes for this type."""
        self._load_attributes()
        return iter(self._attrs)

    def aliases(self):
        """Generator that yields all aliases for this type."""
        self._load_aliases()
        return iter(self._aliases)

    def statement(self):
        cdef:
            size_t count
            str stmt

        self._load_attributes()
        self._load_aliases()
        count = len(self._aliases)

        stmt = "type {0}".format(self.name)
        if count > 1:
            stmt += " alias {{ {0} }}".format(' '.join(self._aliases))
        elif count == 1:
            stmt += " alias {0}".format(self._aliases[0])
        for attr in self._attrs:
            stmt += ", {0}".format(attr)
        stmt += ";"
        return stmt


cdef class TypeAttribute(BaseType):

    """A type attribute."""

    cdef list _types

    @staticmethod
    cdef inline TypeAttribute factory(SELinuxPolicy policy, sepol.type_datum_t *symbol):
        """Factory function for creating TypeAttribute objects."""
        cdef TypeAttribute a
        if symbol.flavor != sepol.TYPE_ATTRIB:
            raise ValueError("{0} is not an attribute".format(
                policy.type_value_to_name(symbol.s.value - 1)))

        try:
            return _typeattr_cache[policy][<uintptr_t>symbol]
        except KeyError:
            a = TypeAttribute.__new__(TypeAttribute)
            _typeattr_cache[policy][<uintptr_t>symbol] = a
            a.policy = policy
            a.key = <uintptr_t>symbol
            a.name = policy.type_value_to_name(symbol.s.value - 1)
            return a

    def __contains__(self, other):
        for type_ in self.expand():
            if other == type_:
                return True

        return False

    def expand(self):
        """Generator that expands this attribute into its member types."""
        cdef sepol.type_datum_t *symbol = <sepol.type_datum_t *>self.key
        if self._types is None:
            self._types = list(TypeEbitmapIterator.factory(self.policy, &symbol.types))

        return iter(self._types)

    def attributes(self):
        """Generator that yields all attributes for this type."""
        raise SymbolUseError("{0} is an attribute, thus does not have attributes.".format(
                             self.name))

    def aliases(self):
        """Generator that yields all aliases for this type."""
        raise SymbolUseError("{0} is an attribute, thus does not have aliases.".format(self.name))

    @property
    def ispermissive(self):
        """(T/F) the type is permissive."""
        raise SymbolUseError("{0} is an attribute, thus cannot be permissive.".format(self.name))

    def statement(self):
        return "attribute {0};".format(self.name)


#
# Hash Table Iterator Classes
#
cdef inline bint type_is_alias(sepol.type_datum_t *datum):
    """Determine if the type datum is an alias."""
    return (datum.primary == 0 and datum.flavor == sepol.TYPE_TYPE) \
            or datum.flavor == sepol.TYPE_ALIAS


cdef class TypeHashtabIterator(HashtabIterator):

    """Iterate over types in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating Role iterators."""
        i = TypeHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        cdef sepol.type_datum_t *datum
        super().__next__()

        datum = <sepol.type_datum_t *> self.curr.datum
        while datum.flavor != sepol.TYPE_TYPE or type_is_alias(datum):
            super().__next__()
            datum = <sepol.type_datum_t *> self.curr.datum

        return Type.factory(self.policy, datum)

    def __len__(self):
        cdef sepol.type_datum_t *datum
        cdef sepol.hashtab_node_t *node
        cdef uint32_t bucket = 0
        cdef size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.type_datum_t *>node.datum if node else NULL
                if datum != NULL and datum.flavor == sepol.TYPE_TYPE and not type_is_alias(datum):
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        super().reset()

        # advance over any attributes or aliases
        while (<sepol.type_datum_t *> self.node.datum).flavor != sepol.TYPE_TYPE:
            self._next_node()


cdef class TypeAttributeHashtabIterator(HashtabIterator):

    """Iterate over type attributes in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating Role iterators."""
        i = TypeAttributeHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        while (<sepol.type_datum_t *> self.curr.datum).flavor != sepol.TYPE_ATTRIB:
            super().__next__()

        return TypeAttribute.factory(self.policy, <sepol.type_datum_t *> self.curr.datum)

    def __len__(self):
        cdef sepol.type_datum_t *datum
        cdef sepol.hashtab_node_t *node
        cdef uint32_t bucket = 0
        cdef size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.type_datum_t *>node.datum if node else NULL
                if datum != NULL and datum.flavor == sepol.TYPE_ATTRIB:
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        super().reset()

        # advance over any attributes or aliases
        while self.node != NULL and (<sepol.type_datum_t *> self.node.datum).flavor != sepol.TYPE_ATTRIB:
            self._next_node()


cdef class TypeAliasHashtabIterator(HashtabIterator):

    """Iterate over type aliases in the policy."""

    cdef uint32_t primary

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table, Type primary):
        """Factory function for creating type alias iterators."""
        i = TypeAliasHashtabIterator()
        i.policy = policy
        i.table = table
        i.primary = primary.value
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        datum = <sepol.type_datum_t *> self.curr.datum if self.curr else NULL

        while datum != NULL and (not type_is_alias(datum) or datum.s.value != self.primary):
            super().__next__()
            datum = <sepol.type_datum_t *> self.curr.datum if self.curr else NULL

        return intern(self.curr.key)

    def __len__(self):
        cdef sepol.type_datum_t *datum
        cdef sepol.hashtab_node_t *node
        cdef uint32_t bucket = 0
        cdef size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.type_datum_t *>node.datum if node else NULL
                if datum != NULL and self.primary == datum.s.value and type_is_alias(datum):
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        super().reset()

        cdef sepol.type_datum_t *datum = <sepol.type_datum_t *> self.node.datum if self.node else NULL

        # advance over any attributes or aliases
        while datum != NULL and (not type_is_alias(datum) and self.primary != datum.s.value):
            self._next_node()

            if self.node == NULL or self.bucket >= self.table[0].size:
                break

            datum = <sepol.type_datum_t *> self.node.datum if self.node else NULL


#
# Ebitmap Iterator Classes
#
cdef class TypeEbitmapIterator(EbitmapIterator):

    """Iterate over a type ebitmap."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ebitmap_t *symbol):
        """Factory function for creating TypeEbitmapIterator."""
        i = TypeEbitmapIterator()
        i.policy = policy
        i.bmap = symbol
        i.reset()
        return i

    @staticmethod
    cdef factory_from_set(SELinuxPolicy policy, sepol.type_set_t *symbol):
        """Factory function for creating TypeEbitmapIterator from a type set."""
        if symbol.flags:
            warnings.warn("* or ~ in the type set; this is not implemented in SETools.")
        if symbol.negset.node != NULL:
            warnings.warn("Negations in the type set; this is not implemented in SETools.")

        return TypeEbitmapIterator.factory(policy, &symbol.types)

    def __next__(self):
        super().__next__()
        return Type.factory(self.policy, self.policy.type_value_to_datum(self.bit))


cdef class TypeAttributeEbitmapIterator(EbitmapIterator):

    """Iterate over a type attribute ebitmap."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ebitmap_t *bmap):
        """Factory function for creating TypeAttributeEbitmapIterator."""
        i = TypeAttributeEbitmapIterator()
        i.policy = policy
        i.bmap = bmap
        i.reset()
        return i

    @staticmethod
    cdef factory_from_set(SELinuxPolicy policy, sepol.type_set_t *symbol):
        """Factory function for creating TypeAttributeEbitmapIterator from a type set."""
        if symbol.flags:
            warnings.warn("* or ~ in the type set; this is not implemented in SETools.")
        if symbol.negset.node != NULL:
            warnings.warn("Negations in the type set; this is not implemented in SETools.")

        return TypeAttributeEbitmapIterator.factory(policy, &symbol.types)

    def __next__(self):
        super().__next__()
        return TypeAttribute.factory(self.policy,
                                     self.policy.type_value_to_datum(self.bit))


cdef class TypeOrAttributeEbitmapIterator(EbitmapIterator):

    """Iterate over a type or type attribute ebitmap."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ebitmap_t *bmap):
        """Factory function for creating TypeAttributeEbitmapIterator."""
        i = TypeOrAttributeEbitmapIterator()
        i.policy = policy
        i.bmap = bmap
        i.reset()
        return i

    @staticmethod
    cdef factory_from_set(SELinuxPolicy policy, sepol.type_set_t *symbol):
        """Factory function for creating TypeAttributeEbitmapIterator from a type set."""
        if symbol.flags:
            warnings.warn("* or ~ in the type set; this is not implemented in SETools.")
        if symbol.negset.node != NULL:
            warnings.warn("Negations in the type set; this is not implemented in SETools.")

        return TypeOrAttributeEbitmapIterator.factory(policy, &symbol.types)

    def __next__(self):
        super().__next__()
        return type_or_attr_factory(self.policy,
                                    self.policy.type_value_to_datum(self.bit))
