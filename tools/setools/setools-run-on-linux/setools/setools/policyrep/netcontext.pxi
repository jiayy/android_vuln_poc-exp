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

IbpkeyconRange = collections.namedtuple("IbpkeyconRange", ["low", "high"])
PortconRange = collections.namedtuple("PortconRange", ["low", "high"])

#
# Classes
#
cdef class Ibendportcon(Ocontext):

    """An ibendportcon statement."""

    cdef:
        readonly str name
        readonly unsigned int port

    @staticmethod
    cdef inline Ibendportcon factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating Ibendportcon objects."""
        cdef Ibendportcon i = Ibendportcon.__new__(Ibendportcon)
        i.policy = policy
        i.key = <uintptr_t>symbol
        i.name = intern(symbol.u.ibendport.dev_name)
        i.port = symbol.u.ibendport.port
        i.context = Context.factory(policy, symbol.context)
        return i

    def __hash__(self):
        return hash("ibendportcon|{0.name}|{0.port}".format(self))

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    def statement(self):
        return "ibendportcon {0.name} {0.port} {0.context}".format(self)


cdef class Ibpkeycon(Ocontext):

    """An ibpkeycon statement."""

    cdef:
        readonly object subnet_prefix
        readonly object pkeys

    @staticmethod
    cdef inline Ibpkeycon factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating Ibpkeycon objects."""
        cdef:
            Ibpkeycon i = Ibpkeycon.__new__(Ibpkeycon)
            char * prefix
            uint32_t *full_address

        i.policy = policy
        i.key = <uintptr_t>symbol
        i.pkeys = IbpkeyconRange(symbol.u.ibpkey.low_pkey, symbol.u.ibpkey.high_pkey)
        i.context = Context.factory(policy, symbol.context)

        #
        # The policy only stores the most significant 64bits of the subnet
        # prefix.  Create a full IPv6 address for inet_ntop use
        #
        full_address = <uint32_t*>PyMem_Malloc(4 * sizeof(uint32_t))
        if full_address == NULL:
            raise MemoryError

        memset(full_address, 0, 4 * sizeof(uint32_t))
        memcpy(full_address, &symbol.u.ibpkey.subnet_prefix, sizeof(uint64_t))

        #
        # Create IPv6Address object for the subnet prefix
        #
        prefix = <char *>PyMem_Malloc(INET6_ADDRSTRLEN * sizeof(char))
        if prefix == NULL:
            PyMem_Free(full_address)
            raise MemoryError

        inet_ntop(AF_INET6, full_address, prefix, INET6_ADDRSTRLEN)
        i.subnet_prefix = ipaddress.IPv6Address(prefix)

        PyMem_Free(full_address)
        PyMem_Free(prefix)
        return i

    def __hash__(self):
        return hash("ibpkeycon|{0.subnet_prefix}|{0.pkeys.low}|{0.pkeys.high}".format(self))

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    def statement(self):
        if self.pkeys.low == self.pkeys.high:
            return "ibpkeycon {0.subnet_prefix} {0.pkeys.low:#x} {0.context}".format(self)
        else:
            return "ibpkeycon {0.subnet_prefix} {0.pkeys.low:#x}-{0.pkeys.high:#x} {0.context}". \
                    format(self)


cdef class Netifcon(Ocontext):

    """A netifcon statement."""

    cdef:
        readonly str netif
        readonly Context packet

    @staticmethod
    cdef inline Netifcon factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating Netifcon objects."""
        cdef Netifcon n = Netifcon.__new__(Netifcon)
        n.policy = policy
        n.key = <uintptr_t>symbol
        n.netif = intern(symbol.u.name)
        n.context = Context.factory(policy, symbol.context)
        n.packet = Context.factory(policy, &symbol.context[1])
        return n

    def __hash__(self):
        return hash("netifcon|{0.netif}".format(self))

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    def statement(self):
        return "netifcon {0.netif} {0.context} {0.packet}".format(self)


class NodeconIPVersion(PolicyEnum):

    """Nodecon IP Version"""

    ipv4 = AF_INET
    ipv6 = AF_INET6


cdef class Nodecon(Ocontext):

    """A nodecon statement."""

    cdef:
        readonly object ip_version
        readonly object network

    @staticmethod
    cdef inline Nodecon factory(SELinuxPolicy policy, sepol.ocontext_t *symbol, ip_version):
        """Factory function for creating Nodecon objects."""
        cdef:
            char * addr
            char * mask
            int CIDR = 0
            int i
            uint32_t block
            Nodecon n = Nodecon.__new__(Nodecon)

        n.policy = policy
        n.key = <uintptr_t>symbol
        n.ip_version = ip_version
        n.context = Context.factory(policy, symbol.context)

        #
        # Retrieve address and netmask
        #
        addr = <char *>PyMem_Malloc(INET6_ADDRSTRLEN * sizeof(char))
        if addr == NULL:
            raise MemoryError

        mask = <char *>PyMem_Malloc(INET6_ADDRSTRLEN * sizeof(char))
        if mask == NULL:
            PyMem_Free(addr)
            raise MemoryError

        #
        # Build network object
        #
        # Python 3.4's IPv6Network constructor does not support
        # expanded netmasks, only CIDR numbers. Convert netmask
        # into CIDR.
        # This is Brian Kernighan's method for counting set bits.
        # If the netmask happens to be invalid, this will
        # not detect it.
        if ip_version == NodeconIPVersion.ipv4:
            # convert network order to string
            inet_ntop(AF_INET, &symbol.u.node.addr, addr, INET6_ADDRSTRLEN)
            inet_ntop(AF_INET, &symbol.u.node.mask, mask, INET6_ADDRSTRLEN)

            # count bits
            block = symbol.u.node.mask
            while block:
                block &= block - 1
                CIDR += 1

        else:  # NodeconIPVersion.ipv6
            # convert network order to string
            inet_ntop(AF_INET6, &symbol.u.node6.addr, addr, INET6_ADDRSTRLEN)
            inet_ntop(AF_INET6, &symbol.u.node6.mask, mask, INET6_ADDRSTRLEN)

            # count bits
            for i in range(4):
                block = symbol.u.node6.mask[i]
                while block:
                    block &= block - 1
                    CIDR += 1

        net_with_mask = "{0}/{1}".format(addr, CIDR)
        try:
            # checkpolicy does not verify that no host bits are set,
            # so strict will raise an exception if host bits are set.
            n.network = ipaddress.ip_network(net_with_mask)
        except ValueError as ex:
            log = logging.getLogger(__name__)
            log.warning("Nodecon with network {} {} has host bits set. Analyses may have "
                        "unexpected results.".format(addr, mask))
            n.network = ipaddress.ip_network(net_with_mask, strict=False)

        PyMem_Free(addr)
        PyMem_Free(mask)

        return n

    def __hash__(self):
        return hash("nodecon|{}".format(self.network.with_netmask))

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    def statement(self):
        return "nodecon {1} {0.context}".format(self, self.network.with_netmask.replace("/", " "))


class PortconProtocol(PolicyEnum):

    """A portcon protocol type."""

    tcp = IPPROTO_TCP
    udp = IPPROTO_UDP
    dccp = IPPROTO_DCCP
    sctp = IPPROTO_SCTP


cdef class Portcon(Ocontext):

    """A portcon statement."""

    cdef:
        readonly object ports
        readonly object protocol

    @staticmethod
    cdef inline Portcon factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating Portcon objects."""
        cdef Portcon p = Portcon.__new__(Portcon)
        p.policy = policy
        p.key = <uintptr_t>symbol
        p.ports = PortconRange(symbol.u.port.low_port, symbol.u.port.high_port)
        p.protocol = PortconProtocol(symbol.u.port.protocol)
        p.context = Context.factory(policy, symbol.context)
        return p

    def __hash__(self):
            return hash("portcon|{0.protocol}|{1.low}|{1.high}".format(self, self.ports))

    def __lt__(self, other):
        # this is used by Python sorting functions
        return str(self) < str(other)

    def statement(self):
        low, high = self.ports

        if low == high:
            return "portcon {0.protocol} {1} {0.context}".format(self, low)
        else:
            return "portcon {0.protocol} {1}-{2} {0.context}".format(self, low, high)


#
# Iterators
#
cdef class IbendportconIterator(OcontextIterator):

    """Iterator for ibendportcon statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating Ibendportcon iterators."""
        i = IbendportconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return Ibendportcon.factory(self.policy, self.ocon)


cdef class IbpkeyconIterator(OcontextIterator):

    """Iterator for ibpkeycon statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating Ibpkeycon iterators."""
        i = IbpkeyconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return Ibpkeycon.factory(self.policy, self.ocon)


cdef class NetifconIterator(OcontextIterator):

    """Iterator for netifcon statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating Netifcon iterators."""
        i = NetifconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return Netifcon.factory(self.policy, self.ocon)


cdef class NodeconIterator(OcontextIterator):

    """Iterator for nodecon statements in the policy."""

    cdef object ip_version

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head, ip_version):
        """Factory function for creating Nodecon iterators."""
        i = NodeconIterator()
        i.policy = policy
        i.head = i.curr = head
        i.ip_version = ip_version
        return i

    def __next__(self):
        super().__next__()
        return Nodecon.factory(self.policy, self.ocon, self.ip_version)


cdef class PortconIterator(OcontextIterator):

    """Iterator for portcon statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating Portcon iterators."""
        i = PortconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return Portcon.factory(self.policy, self.ocon)
