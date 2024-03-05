# Copyright 2017-2018, Chris PeBenito <pebenito@ieee.org>
# Derived from netcontext.py
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

IomemconRange = collections.namedtuple("IomemconRange", ["low", "high"])
IoportconRange = collections.namedtuple("IoportconRange", ["low", "high"])


#
# Classes
#
cdef class Devicetreecon(Ocontext):

    """A devicetreecon statement."""

    cdef readonly str path

    @staticmethod
    cdef inline Devicetreecon factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating Devicetreecon objects."""
        cdef Devicetreecon d = Devicetreecon.__new__(Devicetreecon)
        d.policy = policy
        d.key = <uintptr_t>symbol
        d.path = intern(symbol.u.name)
        d.context = Context.factory(policy, symbol.context)
        return d

    def statement(self):
        return "devicetreecon {0.path} {0.context}".format(self)


cdef class Iomemcon(Ocontext):

    """A iomemcon statement."""

    cdef readonly object addr

    @staticmethod
    cdef inline Iomemcon factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating Iomemcon objects."""
        cdef Iomemcon i = Iomemcon.__new__(Iomemcon)
        i.policy = policy
        i.key = <uintptr_t>symbol
        i.addr = IomemconRange(symbol.u.iomem.low_iomem, symbol.u.iomem.high_iomem)
        i.context = Context.factory(policy, symbol.context)
        return i

    def statement(self):
        low, high = self.addr

        if low == high:
            return "iomemcon {0} {1}".format(low, self.context)
        else:
            return "iomemcon {0}-{1} {2}".format(low, high, self.context)


cdef class Ioportcon(Ocontext):

    """A ioportcon statement."""

    cdef readonly object ports

    @staticmethod
    cdef inline Ioportcon factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating Ioportcon objects."""
        cdef Ioportcon i = Ioportcon.__new__(Ioportcon)
        i.policy = policy
        i.key = <uintptr_t>symbol
        i.ports = IoportconRange(symbol.u.ioport.low_ioport, symbol.u.ioport.high_ioport)
        i.context = Context.factory(policy, symbol.context)
        return i

    def statement(self):
        low, high = self.ports

        if low == high:
            return "ioportcon {0} {1}".format(low, self.context)
        else:
            return "ioportcon {0}-{1} {2}".format(low, high, self.context)


cdef class Pcidevicecon(Ocontext):

    """A pcidevicecon statement."""

    cdef readonly object device

    @staticmethod
    cdef inline Pcidevicecon factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating Pcidevicecon objects."""
        cdef Pcidevicecon p = Pcidevicecon.__new__(Pcidevicecon)
        p.policy = policy
        p.key = <uintptr_t>symbol
        p.device = symbol.u.device
        p.context = Context.factory(policy, symbol.context)
        return p

    def statement(self):
        return "pcidevicecon {0.device} {0.context}".format(self)


cdef class Pirqcon(Ocontext):

    """A pirqcon statement."""

    cdef readonly object irq

    @staticmethod
    cdef inline Pirqcon factory(SELinuxPolicy policy, sepol.ocontext_t *symbol):
        """Factory function for creating Pirqcon objects."""
        cdef Pirqcon p = Pirqcon.__new__(Pirqcon)
        p.policy = policy
        p.key = <uintptr_t>symbol
        p.irq = symbol.u.pirq
        p.context = Context.factory(policy, symbol.context)
        return p

    def statement(self):
        return "pirqcon {0.irq} {0.context}".format(self)


#
# Iterators
#
cdef class DevicetreeconIterator(OcontextIterator):

    """Iterator for devicetreecon statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating Devicetreecon iterators."""
        i = DevicetreeconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return Devicetreecon.factory(self.policy, self.ocon)


cdef class IomemconIterator(OcontextIterator):

    """Iterator for iomemcon statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating Iomemcon iterators."""
        i = IomemconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return Iomemcon.factory(self.policy, self.ocon)


cdef class IoportconIterator(OcontextIterator):

    """Iterator for ioportcon statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating Ioportcon iterators."""
        i = IoportconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return Ioportcon.factory(self.policy, self.ocon)


cdef class PcideviceconIterator(OcontextIterator):

    """Iterator for pcidevicecon statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating Pcidevicecon iterators."""
        i = PcideviceconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return Pcidevicecon.factory(self.policy, self.ocon)


cdef class PirqconIterator(OcontextIterator):

    """Iterator for pirqcon statements in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.ocontext_t *head):
        """Factory function for creating Pirqcon iterators."""
        i = PirqconIterator()
        i.policy = policy
        i.head = i.curr = head
        return i

    def __next__(self):
        super().__next__()
        return Pirqcon.factory(self.policy, self.ocon)
