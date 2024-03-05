# Copyright 2016-2017, Chris PeBenito <pebenito@ieee.org>
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
class PolicyEnum(enum.Enum):

    """
    Base class for policy enumerations.

    Standard Enum behavior except for returning
    the enum name for the default string representation
    and basic string format.
    """

    def __str__(self):
        return self.name

    def __format__(self, spec):
        if not spec:
            return self.name
        else:
            return super(PolicyEnum, self).__format__(spec)

    def __eq__(self, other):
        return super(PolicyEnum, self).__eq__(other)

    def __hash__(self):
        return hash(self.name)

    @classmethod
    def lookup(cls, value):
        """Look up an enumeration by name or value."""

        try:
            return cls(value)
        except ValueError:
            return cls[value]


class WeakKeyDefaultDict(weakref.WeakKeyDictionary):

    """
    A dictionary with a weak-referenced key and a default value.

    This is a combination of WeakKeyDictionary and defaultdict
    classes and has the interfaces of both, with the exception
    of the constructor.

    WeakKeyDefaultDict(default_factory, [dict])
    """

    def __init__(self, default_factory, *args):
        self.default_factory = default_factory
        super().__init__(args)

    def __getitem__(self, key):
        try:
            return super().__getitem__(key)
        except KeyError:
            return self.__missing__(key)

    def __missing__(self, key):
        if self.default_factory is None:
            raise KeyError(key)

        defaultvalue = self.default_factory()
        self.__setitem__(key, defaultvalue)
        return defaultvalue


#
# Functions
#
cdef void sepol_logging_callback(void *varg, sepol.sepol_handle_t * sh, const char *fmt, ...):
    """Python logging for sepol log callback."""
    cdef:
        va_list args
        char *msg

    va_start(args, fmt)
    if vasprintf(&msg, fmt, args) < 0:
        raise MemoryError
    va_end(args)

    logging.getLogger("libsepol").debug(msg)
    free(msg)


cdef void ebitmap_set_bit(sepol.ebitmap_t * e, unsigned int bit, int value):
    """
    Set a specific bit value in an ebitmap.

    This is derived from the libsepol function of the same name.
    """

    cdef:
        sepol.ebitmap_node_t *n
        sepol.ebitmap_node_t *prev
        sepol.ebitmap_node_t *new
        uint32_t startbit = bit & ~(sepol.MAPSIZE - 1)
        uint32_t highbit = startbit + sepol.MAPSIZE

    if highbit == 0:
        raise LowLevelPolicyError("Bitmap overflow, bit {0:#06x}".format(bit))

    prev = NULL
    n = e.node;
    while n and n.startbit <= bit:
        if (n.startbit + sepol.MAPSIZE) > bit:
            if value:
                n.map |= sepol.MAPBIT << (bit - n.startbit)
            else:
                n.map &= ~(sepol.MAPBIT << (bit - n.startbit))
                if not n.map:
                    # drop this node from the bitmap

                    if not n.next:
                        # this was the highest map
                        # within the bitmap
                        if prev:
                                e.highbit = prev.startbit + sepol.MAPSIZE
                        else:
                                e.highbit = 0

                    if prev:
                        prev.next = n.next
                    else:
                        e.node = n.next

                    free(n)

            return

        prev = n
        n = n.next

    if not value:
        return

    new = <sepol.ebitmap_node_t*>calloc(1, sizeof(sepol.ebitmap_node_t))
    if new == NULL:
        raise MemoryError

    new.startbit = startbit;
    new.map = sepol.MAPBIT << (bit - new.startbit)

    if not n:
        # this node will be the highest map within the bitmap
        e.highbit = highbit

    if prev:
        new.next = prev.next
        prev.next = new
    else:
        new.next = e.node
        e.node = new


cdef int hashtab_insert(sepol.hashtab_t h, sepol.hashtab_key_t key, sepol.hashtab_datum_t datum):
    """
    Insert a node into a hash table.

    This is derived from the libsepol function of the same name.
    """

    cdef:
        int hvalue
        sepol.hashtab_ptr_t prev, cur, newnode

    hvalue = h.hash_value(h, key)
    prev = NULL
    cur = h.htable[hvalue]
    while cur and h.keycmp(h, key, cur.key) > 0:
        prev = cur
        cur = cur.next

    if cur and h.keycmp(h, key, cur.key) == 0:
        raise LowLevelPolicyError("Error inserting into hash table.  Key already exists.")

    newnode = <sepol.hashtab_ptr_t> calloc(1, sizeof(sepol.hashtab_node_t))
    if newnode == NULL:
        raise MemoryError

    newnode.key = key;
    newnode.datum = datum;
    if prev:
        newnode.next = prev.next
        prev.next = newnode
    else:
        newnode.next = h.htable[hvalue]
        h.htable[hvalue] = newnode

    h.nel += 1


cdef flatten_list(input_list):
    """
    Flatten a list with nested lists.

    e.g.
    [A, B, [D, E], C]

    turns into:
    [A, B, D, E, C]
    """
    cdef list ret = []

    for i in input_list:
        if isinstance(i, list):
            ret.extend(flatten_list(i))
        else:
            ret.append(i)

    return ret
