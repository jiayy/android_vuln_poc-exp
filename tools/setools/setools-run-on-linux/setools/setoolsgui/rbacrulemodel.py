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
from setools.exception import RuleUseError

from .models import SEToolsTableModel


class RBACRuleTableModel(SEToolsTableModel):

    """A table-based model for RBAC rules."""

    headers = ["Rule Type", "Source", "Target", "Object Class", "Default Role"]

    def data(self, index, role):
        if self.resultlist and index.isValid():
            row = index.row()
            col = index.column()
            rule = self.resultlist[row]

            if role == Qt.DisplayRole:
                if col == 0:
                    return rule.ruletype.name
                elif col == 1:
                    return rule.source.name
                elif col == 2:
                    return rule.target.name
                elif col == 3:
                    try:
                        return rule.tclass.name
                    except RuleUseError:
                        # role allow
                        return None
                elif col == 4:
                    # next most common: default
                    try:
                        return rule.default.name
                    except RuleUseError:
                        return None

            elif role == Qt.UserRole:
                return rule
