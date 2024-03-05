# Copyright 2014-2016, Tresys Technology, LLC
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
# pylint: disable=protected-access

cdef object _cat_cache = WeakKeyDefaultDict(dict)
cdef object _sens_cache = WeakKeyDefaultDict(dict)
cdef object _leveldecl_cache = WeakKeyDefaultDict(dict)


#
# Classes
#
cdef list expand_cat_range(SELinuxPolicy policy, Category low, Category high):
    """
    Helper function to expand a category range, e.g. c0.c1023
    into the full set of categories by using the low and high
    categories of the set.
    """

    cdef list expanded
    expanded = [low, high]
    for value in range(low._value, high._value):
        expanded.append(Category.factory(policy, policy.category_value_to_datum(value)))

    return expanded


cdef class Category(PolicySymbol):

    """An MLS category."""

    cdef:
        readonly uint32_t _value
        list _aliases

    @staticmethod
    cdef inline Category factory(SELinuxPolicy policy, sepol.cat_datum_t *symbol):
        """Factory function for creating Category objects."""
        cdef Category c
        if not policy.mls:
            raise MLSDisabled

        try:
            return _cat_cache[policy][<uintptr_t>symbol]
        except KeyError:
            c = Category.__new__(Category)
            c.policy = policy
            c.key = <uintptr_t>symbol
            c.name = policy.category_value_to_name(symbol.s.value - 1)
            c._value = symbol.s.value
            _cat_cache[policy][<uintptr_t>symbol] = c
            return c

    def __hash__(self):
        return hash(self.name)

    def __lt__(self, other):
        # Comparison based on their index instead of their names.
        return self._value < other._value

    cdef inline void _load_aliases(self):
        """Helper method to load aliases."""
        if self._aliases is None:
            self._aliases = list(self.policy.category_aliases(self))

    def aliases(self):
        """Generator that yields all aliases for this category."""
        self._load_aliases()
        return iter(self._aliases)

    def statement(self):
        cdef:
            str stmt
            size_t count

        self._load_aliases()
        count = len(self._aliases)

        stmt = "category {0}".format(self.name)
        if count > 1:
            stmt += " alias {{ {0} }}".format(' '.join(self._aliases))
        elif count == 1:
            stmt += " alias {0}".format(self._aliases[0])
        stmt += ";"
        return stmt


cdef class Sensitivity(PolicySymbol):

    """An MLS sensitivity"""

    cdef:
        readonly uint32_t _value
        list _aliases
        LevelDecl _leveldecl

    @staticmethod
    cdef inline Sensitivity factory(SELinuxPolicy policy, sepol.level_datum_t *symbol):
        """Factory function for creating Sensitivity objects."""
        cdef Sensitivity s
        if not policy.mls:
            raise MLSDisabled

        try:
            return _sens_cache[policy][<uintptr_t>symbol]
        except KeyError:
            s = Sensitivity.__new__(Sensitivity)
            _sens_cache[policy][<uintptr_t>symbol] = s
            s.policy = policy
            s.key = <uintptr_t>symbol
            s.name = policy.level_value_to_name(symbol.level.sens - 1)
            s._value = symbol.level.sens
            return s

    def __hash__(self):
        return hash(self.name)

    def __ge__(self, other):
        return self._value >= other._value

    def __gt__(self, other):
        return self._value > other._value

    def __le__(self, other):
        return self._value <= other._value

    def __lt__(self, other):
        return self._value < other._value

    cdef inline void _load_aliases(self):
        """Helper method to load aliases."""
        if self._aliases is None:
            self._aliases = list(self.policy.sensitivity_aliases(self))

    def aliases(self):
        """Generator that yields all aliases for this sensitivity."""
        self._load_aliases()
        return iter(self._aliases)

    def level_decl(self):
        """Get the level declaration corresponding to this sensitivity."""
        cdef sepol.level_datum_t *symbol = <sepol.level_datum_t *>self.key
        if self._leveldecl is None:
            self._leveldecl = LevelDecl.factory(self.policy, symbol)

        return self._leveldecl

    def statement(self):
        cdef:
            str stmt
            size_t count

        self._load_aliases()
        count = len(self._aliases)

        stmt = "sensitivity {0}".format(self.name)
        if count > 1:
            stmt += " alias {{ {0} }}".format(' '.join(self._aliases))
        elif count == 1:
            stmt += " alias {0}".format(self._aliases[0])
        stmt += ";"
        return stmt


cdef class BaseMLSLevel(PolicyObject):

    """Base class for MLS levels."""

    cdef:
        set _categories
        readonly Sensitivity sensitivity

    def __str__(self):
        lvl = str(self.sensitivity)

        # sort by policy declaration order
        cats = sorted(self._categories, key=lambda k: k._value)

        if cats:
            # generate short category notation
            shortlist = []
            for _, i in itertools.groupby(cats, key=lambda k,
                                          c=itertools.count(): k._value - next(c)):
                group = list(i)
                if len(group) > 1:
                    shortlist.append("{0}.{1}".format(group[0], group[-1]))
                else:
                    shortlist.append(str(group[0]))

            lvl += ":" + ','.join(shortlist)

        return lvl

    def categories(self):
        """
        Generator that yields all individual categories for this level.
        All categories are yielded, not a compact notation such as
        c0.c255
        """
        return iter(self._categories)


cdef class LevelDecl(BaseMLSLevel):

    """
    The declaration statement for MLS levels, e.g:

    level s7:c0.c1023;
    """

    @staticmethod
    cdef inline LevelDecl factory(SELinuxPolicy policy, sepol.level_datum_t *symbol):
        """Factory function for creating LevelDecl objects."""
        cdef LevelDecl l
        if not policy.mls:
            raise MLSDisabled

        try:
            return _leveldecl_cache[policy][<uintptr_t>symbol]
        except KeyError:
            l = LevelDecl.__new__(LevelDecl)
            _leveldecl_cache[policy][<uintptr_t>symbol] = l
            l.policy = policy
            l._categories = set(CategoryEbitmapIterator.factory(policy, &symbol.level.cat))
            # the datum for levels is also used for Sensitivity objects
            l.sensitivity = Sensitivity.factory(policy, symbol)
            return l

    def __hash__(self):
        return hash(self.sensitivity)

    # below comparisons are only based on sensitivity
    # dominance since, in this context, the allowable
    # category set is being defined for the level.
    # object type is asserted here because this cannot
    # be compared to a Level instance.

    def __eq__(self, other):
        assert not isinstance(other, Level), "Levels cannot be compared to level declarations"

        try:
            return self.sensitivity == other.sensitivity
        except AttributeError:
            return str(self) == str(other)

    def __ge__(self, other):
        assert not isinstance(other, Level), "Levels cannot be compared to level declarations"
        return self.sensitivity >= other.sensitivity

    def __gt__(self, other):
        assert not isinstance(other, Level), "Levels cannot be compared to level declarations"
        return self.sensitivity > other.sensitivity

    def __le__(self, other):
        assert not isinstance(other, Level), "Levels cannot be compared to level declarations"
        return self.sensitivity <= other.sensitivity

    def __lt__(self, other):
        assert not isinstance(other, Level), "Levels cannot be compared to level declarations"
        return self.sensitivity < other.sensitivity

    def statement(self):
        return "level {0};".format(self)


cdef class Level(BaseMLSLevel):

    """
    An MLS level used in contexts.

    The _sensitivity and _categories attributes are only populated
    if the level is user-generated.
    """

    @staticmethod
    cdef inline Level factory(SELinuxPolicy policy, sepol.mls_level_t *symbol):
        """Factory function for creating Level objects."""
        if not policy.mls:
            raise MLSDisabled

        cdef Level l = Level.__new__(Level)
        l.policy = policy
        l.sensitivity = Sensitivity.factory(policy, policy.level_value_to_datum(symbol.sens - 1))
        l._categories = set(CategoryEbitmapIterator.factory(policy, &symbol.cat))
        return l

    @staticmethod
    cdef inline Level factory_from_string(SELinuxPolicy policy, str name):
        """Factory function variant for constructing Level objects by a string."""
        if not policy.mls:
            raise MLSDisabled

        cdef:
            Level l = Level.__new__(Level)
            list sens_split = name.split(":")
            str sens = sens_split[0]
            Sensitivity s
            list c
            str cats
            list catrange
            str group

        l.policy = policy

        try:
            l.sensitivity = policy.lookup_sensitivity(sens)
        except InvalidSensitivity as ex:
            raise InvalidLevel("{0} is not a valid level ({1} is not a valid sensitivity)". \
                               format(name, sens)) from ex

        l._categories = set()

        try:
            cats = sens_split[1]
        except IndexError:
            pass
        else:
            for group in cats.split(","):
                catrange = group.split(".")
                if len(catrange) == 2:
                    try:
                        l._categories.update(expand_cat_range(policy,
                                                              policy.lookup_category(catrange[0]),
                                                              policy.lookup_category(catrange[1])))
                    except InvalidCategory as ex:
                        raise InvalidLevel(
                            "{0} is not a valid level ({1} is not a valid category range)".
                            format(name, group)) from ex

                elif len(catrange) == 1:
                    try:
                        l._categories.add(policy.lookup_category(catrange[0]))
                    except InvalidCategory as ex:
                        raise InvalidLevel("{0} is not a valid level ({1} is not a valid category)".
                                           format(name, group)) from ex

                else:
                    raise InvalidLevel("{0} is not a valid level (level parsing error)".format(name))

        # verify level is valid
        if not l <= l.sensitivity.level_decl():
            raise InvalidLevel(
                "{0} is not a valid level (one or more categories are not associated with the "
                "sensitivity)".format(name))

        return l

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        try:
            othercats = set(other.categories())
        except AttributeError:
            return str(self) == str(other)
        else:
            return self.sensitivity == other.sensitivity and self._categories == othercats

    def __ge__(self, other):
        # Dom operator
        othercats = set(other.categories())
        return self.sensitivity >= other.sensitivity and self._categories >= othercats

    def __gt__(self, other):
        othercats = set(other.categories())
        return ((self.sensitivity > other.sensitivity and self._categories >= othercats) or
                (self.sensitivity >= other.sensitivity and self._categories > othercats))

    def __le__(self, other):
        # Domby operator
        othercats = set(other.categories())
        return self.sensitivity <= other.sensitivity and self._categories <= othercats

    def __lt__(self, other):
        othercats = set(other.categories())
        return ((self.sensitivity < other.sensitivity and self._categories <= othercats) or
                (self.sensitivity <= other.sensitivity and self._categories < othercats))

    def __xor__(self, other):
        # Incomp operator
        return not (self >= other or self <= other)

    def statement(self):
        raise NoStatement


cdef class Range(PolicyObject):

    """An MLS range"""

    cdef:
        readonly Level low
        readonly Level high

    @staticmethod
    cdef inline Range factory(SELinuxPolicy policy, sepol.mls_range_t *symbol):
        """Factory function for creating Range objects."""
        if not policy.mls:
            raise MLSDisabled

        cdef Range r = Range.__new__(Range)
        r.policy = policy
        r.low = Level.factory(policy, &symbol.level[0])
        r.high = Level.factory(policy, &symbol.level[1])
        return r

    @staticmethod
    cdef inline Range factory_from_string(SELinuxPolicy policy, str name):
        """Factory function variant for constructing Range objects by name."""
        if not policy.mls:
            raise MLSDisabled

        cdef Range r = Range.__new__(Range)
        r.policy = policy

        # build range:
        cdef list levels = name.split("-")

        # strip() levels to handle ranges with spaces in them,
        # e.g. s0:c1 - s0:c0.c255
        try:
            r.low  = Level.factory_from_string(policy, levels[0].strip())
        except InvalidLevel as ex:
            raise InvalidRange("{0} is not a valid range ({1}).".format(name, ex)) from ex

        try:
            r.high = Level.factory_from_string(policy, levels[1].strip())
        except InvalidLevel as ex:
            raise InvalidRange("{0} is not a valid range ({1}).".format(name, ex)) from ex
        except IndexError:
            r.high = r.low

        # verify high level dominates low range
        if not r.high >= r.low:
            raise InvalidRange("{0} is not a valid range ({1.low} is not dominated by {1.high})".
                               format(name, r))
        return r

    def __str__(self):
        if self.high == self.low:
            return str(self.low)

        return "{0.low} - {0.high}".format(self)

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        try:
            return self.low == other.low and self.high == other.high
        except AttributeError:
            # remove all spaces in the string representations
            # to handle cases where the other object does not
            # have spaces around the '-'
            other_str = str(other).replace(" ", "")
            self_str = str(self).replace(" ", "")
            return self_str == other_str

    def __contains__(self, other):
        return self.low <= other <= self.high

    def statement(self):
        raise NoStatement


#
# Hash Table Iterators
#
cdef class CategoryHashtabIterator(HashtabIterator):

    """Iterate over categories in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating category iterators."""
        i = CategoryHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        datum = <sepol.cat_datum_t *> self.curr.datum if self.curr else NULL

        while datum != NULL and datum.isalias:
            super().__next__()
            datum = <sepol.cat_datum_t *> self.curr.datum if self.curr else NULL

        return Category.factory(self.policy, datum)

    def __len__(self):
        cdef sepol.cat_datum_t *datum
        cdef sepol.hashtab_node_t *node
        cdef uint32_t bucket = 0
        cdef size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.cat_datum_t *>node.datum if node else NULL
                if datum != NULL and not datum.isalias:
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        super().reset()

        cdef sepol.cat_datum_t *datum = <sepol.cat_datum_t *> self.node.datum if self.node else NULL

        # advance over any attributes or aliases
        while datum != NULL and datum.isalias:
            self._next_node()

            if self.node == NULL or self.bucket >= self.table[0].size:
                break

            datum = <sepol.cat_datum_t *> self.node.datum if self.node else NULL


cdef class CategoryAliasHashtabIterator(HashtabIterator):

    """Iterate over category aliases in the policy."""

    cdef uint32_t primary

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table, Category primary):
        """Factory function for creating category alias iterators."""
        i = CategoryAliasHashtabIterator()
        i.policy = policy
        i.table = table
        i.primary = primary._value
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        datum = <sepol.cat_datum_t *> self.curr.datum if self.curr else NULL

        while datum != NULL and (not datum.isalias or datum.s.value != self.primary):
            super().__next__()
            datum = <sepol.cat_datum_t *> self.curr.datum if self.curr else NULL

        return intern(self.curr.key)

    def __len__(self):
        cdef sepol.cat_datum_t *datum
        cdef sepol.hashtab_node_t *node
        cdef uint32_t bucket = 0
        cdef size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.cat_datum_t *>node.datum if node else NULL
                if datum != NULL and self.primary == datum.s.value and datum.isalias:
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        super().reset()

        cdef sepol.cat_datum_t *datum = <sepol.cat_datum_t *> self.node.datum if self.node else NULL

        # advance over any attributes or aliases
        while datum != NULL and (not datum.isalias and self.primary != datum.s.value):
            self._next_node()

            if self.node == NULL or self.bucket >= self.table[0].size:
                break

            datum = <sepol.cat_datum_t *> self.node.datum if self.node else NULL


cdef class SensitivityHashtabIterator(HashtabIterator):

    """Iterate over sensitivity in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating category iterators."""
        i = SensitivityHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        datum = <sepol.level_datum_t *> self.curr.datum if self.curr else NULL

        while datum != NULL and datum.isalias:
            super().__next__()
            datum = <sepol.level_datum_t *> self.curr.datum if self.curr else NULL

        return Sensitivity.factory(self.policy, datum)

    def __len__(self):
        cdef sepol.level_datum_t *datum
        cdef sepol.hashtab_node_t *node
        cdef uint32_t bucket = 0
        cdef size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.level_datum_t *>node.datum if node else NULL
                if datum != NULL and not datum.isalias:
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        super().reset()

        cdef sepol.level_datum_t *datum = <sepol.level_datum_t *> self.node.datum if self.node else NULL

        # advance over any attributes or aliases
        while datum != NULL and datum.isalias:
            self._next_node()

            if self.node == NULL or self.bucket >= self.table[0].size:
                break

            datum = <sepol.level_datum_t *> self.node.datum if self.node else NULL


cdef class SensitivityAliasHashtabIterator(HashtabIterator):

    """Iterate over sensitivity aliases in the policy."""

    cdef uint32_t primary

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table, Sensitivity primary):
        """Factory function for creating Sensitivity alias iterators."""
        i = SensitivityAliasHashtabIterator()
        i.policy = policy
        i.table = table
        i.primary = primary._value
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        datum = <sepol.level_datum_t *> self.curr.datum if self.curr else NULL

        while datum != NULL and (not datum.isalias or datum.level.sens != self.primary):
            super().__next__()
            datum = <sepol.level_datum_t *> self.curr.datum if self.curr else NULL

        return intern(self.curr.key)

    def __len__(self):
        cdef sepol.level_datum_t *datum
        cdef sepol.hashtab_node_t *node
        cdef uint32_t bucket = 0
        cdef size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.level_datum_t *>node.datum if node else NULL
                if datum != NULL and self.primary == datum.level.sens and datum.isalias:
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        super().reset()

        cdef sepol.level_datum_t *datum = <sepol.level_datum_t *> self.node.datum if self.node else NULL

        # advance over any attributes or aliases
        while datum != NULL and (not datum.isalias and self.primary != datum.level.sens):
            self._next_node()

            if self.node == NULL or self.bucket >= self.table[0].size:
                break

            datum = <sepol.level_datum_t *> self.node.datum if self.node else NULL


cdef class LevelDeclHashtabIterator(HashtabIterator):

    """Iterate over level declarations in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating level declarations iterators."""
        i = LevelDeclHashtabIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        datum = <sepol.level_datum_t *> self.curr.datum if self.curr else NULL

        while datum != NULL and datum.isalias:
            super().__next__()
            datum = <sepol.level_datum_t *> self.curr.datum if self.curr else NULL

        return LevelDecl.factory(self.policy, datum)

    def __len__(self):
        cdef sepol.level_datum_t *datum
        cdef sepol.hashtab_node_t *node
        cdef uint32_t bucket = 0
        cdef size_t count = 0

        while bucket < self.table[0].size:
            node = self.table[0].htable[bucket]
            while node != NULL:
                datum = <sepol.level_datum_t *>node.datum if node else NULL
                if datum != NULL and not datum.isalias:
                    count += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        super().reset()

        cdef sepol.level_datum_t *datum = <sepol.level_datum_t *> self.node.datum if self.node else NULL

        # advance over any attributes or aliases
        while datum != NULL and datum.isalias:
            self._next_node()

            if self.node == NULL or self.bucket >= self.table[0].size:
                break

            datum = <sepol.level_datum_t *> self.node.datum if self.node else NULL


#
# Ebitmap Iterators
#
cdef class CategoryEbitmapIterator(EbitmapIterator):

    """Iterate over a category ebitmap."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ebitmap_t *symbol):
        """Factory function for creating CategoryEbitmapIterator."""
        i = CategoryEbitmapIterator()
        i.policy = policy
        i.bmap = symbol
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return Category.factory(self.policy, self.policy.category_value_to_datum(self.bit))
