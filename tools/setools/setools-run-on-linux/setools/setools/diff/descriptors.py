# Copyright 2015, Tresys Technology, LLC
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
from weakref import WeakKeyDictionary


class DiffResultDescriptor:

    """Descriptor for managing diff results."""

    # @properties could be used instead, but there are so
    # many result attributes, this will keep the code cleaner.

    def __init__(self, diff_function):
        self.diff_function = diff_function

        # use weak references so instances can be
        # garbage collected, rather than unnecessarily
        # kept around due to this descriptor.
        self.instances = WeakKeyDictionary()

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self

        if self.instances.setdefault(obj, None) is None:
            diff = getattr(obj, self.diff_function)
            diff()

        return self.instances[obj]

    def __set__(self, obj, value):
        self.instances[obj] = value

    def __delete__(self, obj):
        self.instances[obj] = None
