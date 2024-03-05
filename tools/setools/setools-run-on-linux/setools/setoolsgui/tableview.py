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
import csv

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QKeySequence, QCursor
from PyQt5.QtWidgets import QAction, QApplication, QFileDialog, QMenu, QTableView


class SEToolsTableView(QTableView):

    """QTableView class extended for SETools use."""

    def __init__(self, parent):
        super(SEToolsTableView, self).__init__(parent)

        # set up right-click context menu
        self.save_csv_action = QAction("Save table to CSV...", self)
        self.menu = QMenu(self)
        self.menu.addAction(self.save_csv_action)

        # connect signals
        self.save_csv_action.triggered.connect(self.choose_csv_save_location)

    def contextMenuEvent(self, event):
        self.menu.popup(QCursor.pos())

    def event(self, e):
        if e == QKeySequence.Copy or e == QKeySequence.Cut:
            datamodel = self.model()

            selected_text = []
            current_row = None
            current_col = None
            prev_row = None
            prev_col = None
            for index in sorted(self.selectionModel().selectedIndexes()):
                current_row = index.row()
                current_col = index.column()

                if prev_row is not None and current_row != prev_row:
                    selected_text.append('\n')
                elif prev_col is not None and current_col != prev_col:
                    selected_text.append('\t')

                selected_text.append(datamodel.data(index, Qt.DisplayRole))

                prev_row = current_row
                prev_col = current_col

            QApplication.clipboard().setText("".join(selected_text))
            return True

        else:
            return super(SEToolsTableView, self).event(e)

    def choose_csv_save_location(self):
        filename = QFileDialog.getSaveFileName(self, "Save to CSV", "table.csv",
                                               "Comma Separated Values Spreadsheet (*.csv);;"
                                               "All Files (*)")[0]

        if filename:
            self.save_csv(filename)

    def save_csv(self, filename):
        """Save the current table data to the specified CSV file."""

        datamodel = self.model()
        row_count = datamodel.rowCount()
        col_count = datamodel.columnCount()

        with open(filename, 'w') as fd:
            writer = csv.writer(fd, quoting=csv.QUOTE_MINIMAL)

            # write headers
            csv_row = []
            for col in range(col_count):
                csv_row.append(datamodel.headerData(col, Qt.Horizontal, Qt.DisplayRole))

            writer.writerow(csv_row)

            # write data
            for row in range(row_count):
                csv_row = []

                for col in range(col_count):
                    index = datamodel.index(row, col)
                    csv_row.append(datamodel.data(index, Qt.DisplayRole))

                writer.writerow(csv_row)
