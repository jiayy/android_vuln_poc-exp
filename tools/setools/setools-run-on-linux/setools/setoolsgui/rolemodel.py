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

from setools.exception import MLSDisabled

from .details import DetailsPopup
from .models import SEToolsTableModel


def role_detail(parent, role):
    """
    Create a dialog box for role details.

    Parameters:
    parent      The parent Qt Widget
    role        The role
    """

    detail = DetailsPopup(parent, "Role detail: {0}".format(role))

    types = sorted(role.types())
    detail.append_header("Types ({0}): ".format(len(types)))

    for t in types:
        detail.append("    {0}".format(t))

    detail.show()


class RoleTableModel(SEToolsTableModel):

    """Table-based model for roles."""

    headers = ["Name", "Types"]

    def data(self, index, role):
        # There are two roles here.
        # The parameter, role, is the Qt role
        # The below item is a role in the list.
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            item = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    return item.name
                elif col == 1:
                    return ", ".join(sorted(t.name for t in item.types()))
            elif role == Qt.UserRole:
                # get the whole object
                return item
