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
from PyQt5.QtCore import Qt, QModelIndex
from setools.exception import MLSDisabled

from .details import DetailsPopup
from .models import SEToolsTableModel


def user_detail(parent, user):
    """
    Create a dialog box for user details.

    Parameters:
    parent      The parent Qt Widget
    user        The user
    """

    detail = DetailsPopup(parent, "User detail: {0}".format(user))

    roles = sorted(user.roles)
    detail.append_header("Roles ({0}):".format(len(roles)))

    for role in roles:
        detail.append("    {0}".format(role))

    try:
        level = user.mls_level
        range_ = user.mls_range
    except MLSDisabled:
        pass
    else:
        detail.append_header("\nDefault MLS Level:")
        detail.append("    {0}".format(level))
        detail.append_header("\nMLS Range:")
        detail.append("    {0}".format(range_))

    detail.show()


class UserTableModel(SEToolsTableModel):

    """Table-based model for users."""

    headers = ["Name", "Roles", "Default Level", "Range"]

    def __init__(self, parent, mls):
        super(UserTableModel, self).__init__(parent)
        self.col_count = 4 if mls else 2

    def columnCount(self, parent=QModelIndex()):
        return self.col_count

    def data(self, index, role):
        if self.resultlist and index.isValid():
            if role == Qt.DisplayRole:
                row = index.row()
                col = index.column()
                user = self.resultlist[row]

                if col == 0:
                    return user.name
                elif col == 1:
                    return ", ".join(sorted(r.name for r in user.roles))
                elif col == 2:
                    try:
                        return str(user.mls_level)
                    except MLSDisabled:
                        return None
                elif col == 3:
                    try:
                        return str(user.mls_range)
                    except MLSDisabled:
                        return None

            elif role == Qt.UserRole:
                return user
