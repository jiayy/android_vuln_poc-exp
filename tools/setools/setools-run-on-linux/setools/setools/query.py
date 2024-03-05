# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
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
from abc import ABC, abstractmethod


class PolicyQuery(ABC):

    """Abstract base class for SELinux policy queries."""

    def __init__(self, policy, **kwargs):
        self.policy = policy

        # keys are sorted in reverse order so regex settings
        # are set before the criteria, e.g. name_regex
        # is set before name.  This ensures correct behavior
        # since the criteria descriptors are sensitve to
        # regex settings.
        for name in sorted(kwargs.keys(), reverse=True):
            attr = getattr(self, name, None)  # None is not callable
            if callable(attr):
                raise ValueError("Keyword parameter {0} conflicts with a callable.".format(name))

            setattr(self, name, kwargs[name])

    @abstractmethod
    def results(self):
        """
        Generator which returns the matches for the query.  This method
        should be overridden by subclasses.
        """
        pass
