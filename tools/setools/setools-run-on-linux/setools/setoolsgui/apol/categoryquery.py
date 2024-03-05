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

import logging

from PyQt5.QtCore import Qt, QSortFilterProxyModel, QStringListModel, QThread
from PyQt5.QtGui import QPalette, QTextCursor
from PyQt5.QtWidgets import QCompleter, QHeaderView, QMessageBox, QProgressDialog
from setools import CategoryQuery

from ..logtosignal import LogHandlerToSignal
from ..models import SEToolsListModel, invert_list_selection
from ..mlsmodel import MLSComponentTableModel, category_detail
from .analysistab import AnalysisTab
from .exception import TabFieldError
from .queryupdater import QueryResultsUpdater
from .workspace import load_checkboxes, load_lineedits, load_textedits, \
    save_checkboxes, save_lineedits, save_textedits


class CategoryQueryTab(AnalysisTab):

    """Category browser and query tab."""

    def __init__(self, parent, policy, perm_map):
        super(CategoryQueryTab, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.policy = policy
        self.query = CategoryQuery(policy)
        self.setupUi()

    def __del__(self):
        self.thread.quit()
        self.thread.wait(5000)
        logging.getLogger("setools.categoryquery").removeHandler(self.handler)

    def setupUi(self):
        self.load_ui("apol/categoryquery.ui")

        # populate category list
        self.category_model = SEToolsListModel(self)
        self.category_model.item_list = sorted(self.policy.categories())
        self.cats.setModel(self.category_model)

        # set up results
        self.table_results_model = MLSComponentTableModel(self)
        self.sort_proxy = QSortFilterProxyModel(self)
        self.sort_proxy.setSourceModel(self.table_results_model)
        self.table_results.setModel(self.sort_proxy)
        self.table_results.sortByColumn(0, Qt.AscendingOrder)

        # setup indications of errors on level/range
        self.errors = set()
        self.orig_palette = self.name.palette()
        self.error_palette = self.name.palette()
        self.error_palette.setColor(QPalette.Base, Qt.red)
        self.clear_name_error()

        # set up processing thread
        self.thread = QThread()
        self.worker = QueryResultsUpdater(self.query, self.table_results_model)
        self.worker.moveToThread(self.thread)
        self.worker.raw_line.connect(self.raw_results.appendPlainText)
        self.worker.finished.connect(self.update_complete)
        self.worker.finished.connect(self.thread.quit)
        self.thread.started.connect(self.worker.update)

        # create a "busy, please wait" dialog
        self.busy = QProgressDialog(self)
        self.busy.setModal(True)
        self.busy.setRange(0, 0)
        self.busy.setMinimumDuration(0)
        self.busy.canceled.connect(self.thread.requestInterruption)
        self.busy.reset()

        # update busy dialog from query INFO logs
        self.handler = LogHandlerToSignal()
        self.handler.message.connect(self.busy.setLabelText)
        logging.getLogger("setools.categoryquery").addHandler(self.handler)

        # Ensure settings are consistent with the initial .ui state
        self.notes.setHidden(not self.notes_expander.isChecked())

        # connect signals
        self.cats.doubleClicked.connect(self.get_detail)
        self.cats.get_detail.triggered.connect(self.get_detail)
        self.name.textEdited.connect(self.clear_name_error)
        self.name.editingFinished.connect(self.set_name)
        self.name_regex.toggled.connect(self.set_name_regex)
        self.buttonBox.clicked.connect(self.run)

    #
    # Category browser
    #
    def get_detail(self):
        # .ui is set for single item selection.
        index = self.cats.selectedIndexes()[0]
        item = self.category_model.data(index, Qt.UserRole)

        self.log.debug("Generating detail window for {0}".format(item))
        category_detail(self, item)

    #
    # Name criteria
    #
    def clear_name_error(self):
        self.clear_criteria_error(self.name, "Match the category name.")

    def set_name(self):
        try:
            self.query.name = self.name.text()
        except Exception as ex:
            self.log.error("Category name error: {0}".format(ex))
            self.set_criteria_error(self.name, ex)

    def set_name_regex(self, state):
        self.log.debug("Setting name_regex {0}".format(state))
        self.query.name_regex = state
        self.clear_name_error()
        self.set_name()

    #
    # Save/Load tab
    #
    def save(self):
        """Return a dictionary of settings."""
        if self.errors:
            raise TabFieldError("Field(s) are in error: {0}".
                                format(" ".join(o.objectName() for o in self.errors)))

        settings = {}
        save_checkboxes(self, settings, ["criteria_expander", "notes_expander", "name_regex"])
        save_lineedits(self, settings, ["name"])
        save_textedits(self, settings, ["notes"])
        return settings

    def load(self, settings):
        load_checkboxes(self, settings, ["criteria_expander", "notes_expander", "name_regex"])
        load_lineedits(self, settings, ["name"])
        load_textedits(self, settings, ["notes"])

    #
    # Results runner
    #

    def run(self, button):
        # right now there is only one button.

        # start processing
        self.busy.setLabelText("Processing query...")
        self.busy.show()
        self.raw_results.clear()
        self.thread.start()

    def update_complete(self, count):
        self.log.info("{0} categories found.".format(count))

        # update sizes/location of result displays
        if not self.busy.wasCanceled():
            self.busy.setLabelText("Resizing the result table's columns; GUI may be unresponsive")
            self.busy.repaint()
            self.table_results.resizeColumnsToContents()
            # If the attrs or alias column widths are too long, pull back
            # to a reasonable size
            header = self.table_results.horizontalHeader()
            if header.sectionSize(1) > 400:
                header.resizeSection(1, 400)
            if header.sectionSize(2) > 400:
                header.resizeSection(2, 400)

        if not self.busy.wasCanceled():
            self.busy.setLabelText("Resizing the result table's rows; GUI may be unresponsive")
            self.busy.repaint()
            self.table_results.resizeRowsToContents()

        if not self.busy.wasCanceled():
            self.busy.setLabelText("Moving the raw result to top; GUI may be unresponsive")
            self.busy.repaint()
            self.raw_results.moveCursor(QTextCursor.Start)

        self.busy.reset()
