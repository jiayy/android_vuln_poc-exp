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


def type_detail(parent, type_):
    """
    Create a dialog box for type details.

    Parameters:
    parent      The parent Qt Widget
    type_       The type
    """

    detail = DetailsPopup(parent, "Type detail: {0}".format(type_))

    detail.append_header("Permissive: {0}\n".format("Yes" if type_.ispermissive else "No"))

    attrs = sorted(type_.attributes())
    detail.append_header("Attributes ({0}):".format(len(attrs)))
    for a in attrs:
        detail.append("    {0}".format(a))

    aliases = sorted(type_.aliases())
    detail.append_header("\nAliases ({0}):".format(len(aliases)))
    for a in aliases:
        detail.append("    {0}".format(a))

    detail.show()


class TypeTableModel(SEToolsTableModel):

    """Table-based model for types."""

    headers = ["Name", "Attributes", "Aliases", "Permissive"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            item = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    return item.name
                elif col == 1:
                    return ", ".join(sorted(a.name for a in item.attributes()))
                elif col == 2:
                    return ", ".join(sorted(a for a in item.aliases()))
                elif col == 3 and item.ispermissive:
                    return "Permissive"

            elif role == Qt.UserRole:
                return item
