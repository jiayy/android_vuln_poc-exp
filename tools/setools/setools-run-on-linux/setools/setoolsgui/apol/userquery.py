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
from setools import UserQuery

from ..logtosignal import LogHandlerToSignal
from ..models import SEToolsListModel, invert_list_selection
from ..usermodel import UserTableModel, user_detail
from .analysistab import AnalysisTab
from .exception import TabFieldError
from .queryupdater import QueryResultsUpdater
from .workspace import load_checkboxes, load_lineedits, load_listviews, load_textedits, \
    save_checkboxes, save_lineedits, save_listviews, save_textedits


class UserQueryTab(AnalysisTab):

    """User browser and query tab."""

    def __init__(self, parent, policy, perm_map):
        super(UserQueryTab, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.policy = policy
        self.query = UserQuery(policy)
        self.setupUi()

    def __del__(self):
        self.thread.quit()
        self.thread.wait(5000)
        logging.getLogger("setools.userquery").removeHandler(self.handler)

    def setupUi(self):
        self.load_ui("apol/userquery.ui")

        # populate user list
        self.user_model = SEToolsListModel(self)
        self.user_model.item_list = sorted(self.policy.users())
        self.users.setModel(self.user_model)

        # populate role list
        self.role_model = SEToolsListModel(self)
        self.role_model.item_list = sorted(r for r in self.policy.roles() if r != "object_r")
        self.roles.setModel(self.role_model)

        # set up results
        self.table_results_model = UserTableModel(self, self.policy.mls)
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

        if self.policy.mls:
            self.clear_level_error()
            self.clear_range_error()
        else:
            # disable level and range criteria
            self.level_criteria.setEnabled(False)
            self.level_criteria.setToolTip("MLS is disabled in this policy.")
            self.level.setToolTip("MLS is disabled in this policy.")
            self.level_exact.setToolTip("MLS is disabled in this policy.")
            self.level_dom.setToolTip("MLS is disabled in this policy.")
            self.level_domby.setToolTip("MLS is disabled in this policy.")
            self.range_criteria.setEnabled(False)
            self.range_criteria.setToolTip("MLS is disabled in this policy.")
            self.range_.setToolTip("MLS is disabled in this policy.")
            self.range_exact.setToolTip("MLS is disabled in this policy.")
            self.range_overlap.setToolTip("MLS is disabled in this policy.")
            self.range_subset.setToolTip("MLS is disabled in this policy.")
            self.range_superset.setToolTip("MLS is disabled in this policy.")

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
        logging.getLogger("setools.userquery").addHandler(self.handler)

        # Ensure settings are consistent with the initial .ui state
        self.notes.setHidden(not self.notes_expander.isChecked())

        # connect signals
        self.users.doubleClicked.connect(self.get_detail)
        self.users.get_detail.triggered.connect(self.get_detail)
        self.name.textEdited.connect(self.clear_name_error)
        self.name.editingFinished.connect(self.set_name)
        self.name_regex.toggled.connect(self.set_name_regex)
        self.roles.selectionModel().selectionChanged.connect(self.set_roles)
        self.invert_roles.clicked.connect(self.invert_role_selection)
        self.level.textEdited.connect(self.clear_level_error)
        self.level.editingFinished.connect(self.set_level)
        self.range_.textEdited.connect(self.clear_range_error)
        self.range_.editingFinished.connect(self.set_range)
        self.buttonBox.clicked.connect(self.run)

    #
    # User browser
    #
    def get_detail(self):
        # .ui is set for single item selection.
        index = self.users.selectedIndexes()[0]
        item = self.user_model.data(index, Qt.UserRole)

        self.log.debug("Generating detail window for {0}".format(item))
        user_detail(self, item)

    #
    # Name criteria
    #
    def clear_name_error(self):
        self.clear_criteria_error(self.name, "Match the user name.")

    def set_name(self):
        try:
            self.query.name = self.name.text()
        except Exception as ex:
            self.log.error("User name error: {0}".format(ex))
            self.set_criteria_error(self.name, ex)

    def set_name_regex(self, state):
        self.log.debug("Setting name_regex {0}".format(state))
        self.query.name_regex = state
        self.clear_name_error()
        self.set_name()

    #
    # Role criteria
    #
    def set_roles(self):
        selected_roles = []
        for index in self.roles.selectionModel().selectedIndexes():
            selected_roles.append(self.role_model.data(index, Qt.UserRole))

        self.query.roles = selected_roles

    def invert_role_selection(self):
        invert_list_selection(self.roles.selectionModel())

    #
    # Default level criteria
    #
    def clear_level_error(self):
        self.clear_criteria_error(self.level, "Match the default level of the user.")

    def set_level(self):
        try:
            self.query.level = self.level.text()
        except Exception as ex:
            self.log.info("Level criterion error: " + str(ex))
            self.set_criteria_error(self.level, ex)

    #
    # Range criteria
    #
    def clear_range_error(self):
        self.clear_criteria_error(self.range_, "Match the default range of the user.")

    def set_range(self):
        try:
            self.query.range_ = self.range_.text()
        except Exception as ex:
            self.log.info("Range criterion error: " + str(ex))
            self.set_criteria_error(self.range_, ex)

    #
    # Save/Load tab
    #
    def save(self):
        """Return a dictionary of settings."""
        if self.errors:
            raise TabFieldError("Field(s) are in error: {0}".
                                format(" ".join(o.objectName() for o in self.errors)))

        settings = {}
        save_checkboxes(self, settings, ["criteria_expander", "notes_expander", "name_regex",
                                         "roles_any", "roles_equal", "level_exact", "level_dom",
                                         "level_domby", "range_exact", "range_overlap",
                                         "range_subset", "range_superset"])
        save_lineedits(self, settings, ["name", "level", "range_"])
        save_listviews(self, settings, ["roles"])
        save_textedits(self, settings, ["notes"])
        return settings

    def load(self, settings):
        load_checkboxes(self, settings, ["criteria_expander", "notes_expander", "name_regex",
                                         "roles_any", "roles_equal", "level_exact", "level_dom",
                                         "level_domby", "range_exact", "range_overlap",
                                         "range_subset", "range_superset"])
        load_lineedits(self, settings, ["name", "level", "range_"])
        load_listviews(self, settings, ["roles"])
        load_textedits(self, settings, ["notes"])

    #
    # Results runner
    #

    def run(self, button):
        # right now there is only one button.
        self.query.roles_equal = self.roles_equal.isChecked()
        self.query.level_dom = self.level_dom.isChecked()
        self.query.level_domby = self.level_domby.isChecked()
        self.query.range_overlap = self.range_overlap.isChecked()
        self.query.range_subset = self.range_subset.isChecked()
        self.query.range_superset = self.range_superset.isChecked()

        # start processing
        self.busy.setLabelText("Processing query...")
        self.busy.show()
        self.raw_results.clear()
        self.thread.start()

    def update_complete(self, count):
        self.log.info("{0} user(s) found.".format(count))

        # update sizes/location of result displays
        if not self.busy.wasCanceled():
            self.busy.setLabelText("Resizing the result table's columns; GUI may be unresponsive")
            self.busy.repaint()
            self.table_results.resizeColumnsToContents()

        if not self.busy.wasCanceled():
            self.busy.setLabelText("Resizing the result table's rows; GUI may be unresponsive")
            self.busy.repaint()
            self.table_results.resizeRowsToContents()

        if not self.busy.wasCanceled():
            self.busy.setLabelText("Moving the raw result to top; GUI may be unresponsive")
            self.busy.repaint()
            self.raw_results.moveCursor(QTextCursor.Start)

        self.busy.reset()
