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
import sys
from errno import ENOENT

import pkg_resources
from PyQt5.uic import loadUi


# Stylesheet that adds a frame around QGroupBoxes
stylesheet = "\
QGroupBox {\
    border: 1px solid lightgrey;\
    margin-top: 0.5em;\
    }\
\
QGroupBox::title {\
    subcontrol-origin: margin;\
    left: 10px;\
    padding: 0 3px 0 3px;\
}\
"


class SEToolsWidget:
    def load_ui(self, filename):
        distro = pkg_resources.get_distribution("setools")
        path = "{0}/setoolsgui/{1}".format(distro.location, filename)
        loadUi(path, self)

        self.setStyleSheet(stylesheet)
