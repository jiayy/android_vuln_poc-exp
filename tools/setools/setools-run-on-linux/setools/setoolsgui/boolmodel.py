# Copyright 2016, Tresys Technology, LLC
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
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QTextCursor

from .details import DetailsPopup
from .models import SEToolsTableModel


def boolean_detail(parent, boolean):
    """
    Create a dialog box for Booleanean details.

    Parameters:
    parent      The parent Qt Widget
    bool        The boolean
    """

    detail = DetailsPopup(parent, "Boolean detail: {0}".format(boolean))

    detail.append_header("Default State: {0}".format(boolean.state))

    detail.show()


class BooleanTableModel(SEToolsTableModel):

    """Table-based model for booleans."""

    headers = ["Name", "Default State"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            boolean = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    return boolean.name
                elif col == 1:
                    return str(boolean.state)

            elif role == Qt.UserRole:
                # get the whole rule for boolean boolean
                return boolean
