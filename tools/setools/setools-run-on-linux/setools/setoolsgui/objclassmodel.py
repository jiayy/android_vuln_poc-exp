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
from itertools import chain

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QTextCursor

from setools.exception import NoCommon

from .details import DetailsPopup
from .models import SEToolsTableModel


def class_detail(parent, class_):
    """
    Create a dialog box for object class details.

    Parameters:
    parent      The parent Qt Widget
    class_      The type
    """

    detail = DetailsPopup(parent, "Object class detail: {0}".format(class_))

    try:
        common = class_.common
    except NoCommon:
        pass
    else:
        detail.append_header("Inherits: {0}\n".format(common))

        detail.append_header("Inherited permissions ({0}):".format(len(common.perms)))

        for p in sorted(common.perms):
            detail.append("    {0}".format(p))

        detail.append("\n")

    detail.append_header("Permissions ({0}):".format(len(class_.perms)))
    for p in sorted(class_.perms):
        detail.append("    {0}".format(p))

    detail.show()


class ObjClassTableModel(SEToolsTableModel):

    """Table-based model for object classes."""

    headers = ["Name", "Permissions"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            item = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    return item.name
                elif col == 1:
                    try:
                        com_perms = item.common.perms
                    except NoCommon:
                        com_perms = []

                    return ", ".join(sorted(chain(com_perms, item.perms)))

            elif role == Qt.UserRole:
                return item
