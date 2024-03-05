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


def _mls_detail(parent, obj, objtype):
    """
    Create a dialog box for category or sensitivity details.

    Parameters:
    parent      The parent Qt Widget
    type_       The type
    """

    detail = DetailsPopup(parent, "{0} detail: {1}".format(objtype, obj))

    aliases = sorted(obj.aliases())
    detail.append_header("Aliases ({0}):".format(len(aliases)))
    for a in aliases:
        detail.append("    {0}".format(a))

    detail.show()


def category_detail(parent, obj):
    """
    Create a dialog box for category details.

    Parameters:
    parent      The parent Qt Widget
    type_       The type
    """
    _mls_detail(parent, obj, "Category")


def sensitivity_detail(parent, obj):
    """
    Create a dialog box for sensitivity details.

    Parameters:
    parent      The parent Qt Widget
    type_       The type
    """
    _mls_detail(parent, obj, "Sensitivity")


class MLSComponentTableModel(SEToolsTableModel):

    """Table-based model for sensitivities and categories."""

    headers = ["Name", "Aliases"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            item = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    return item.name
                elif col == 1:
                    return ", ".join(sorted(a for a in item.aliases()))

            elif role == Qt.UserRole:
                return item
