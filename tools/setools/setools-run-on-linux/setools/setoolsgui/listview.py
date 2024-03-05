# Copyright 2016, Chris PeBenito <pebenito@ieee.org>
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
import logging
from collections import defaultdict

from PyQt5.QtCore import Qt, QItemSelectionModel
from PyQt5.QtGui import QKeySequence
from PyQt5.QtWidgets import QAbstractItemView, QListView


class SEToolsListView(QListView):

    """QListView class extended for SETools use."""

    def __init__(self, parent):
        super(SEToolsListView, self).__init__(parent)
        self.log = logging.getLogger(__name__)

    def invert(self):
        """Invert the selection."""
        if self.selectionMode() != QAbstractItemView.ExtendedSelection and \
                self.selectionMode() != QAbstractItemView.MultiSelection:

            self.log.debug("Attempted to invert list {0} which doesn't have multiselect.".
                           format(self.objectName()))

            return

        selection_model = self.selectionModel()
        model = self.model()

        for row in range(model.rowCount()):
            index = model.createIndex(row, 0)
            selection_model.select(index, QItemSelectionModel.Toggle)

    def selection(self, qt_role=Qt.UserRole):
        """
        Generator which returns the selection.

        Parameter:
        qt_role     The Qt model role. Default is Qt.UserRole.

        Yield: tuple(row, data)
        row         The row number of the selection.
        data        The data for the row, for the specified Qt role.
        """
        model = self.model()
        for index in self.selectionModel().selectedIndexes():
            yield index.row(), model.data(index, qt_role)
