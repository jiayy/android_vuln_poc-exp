# Copyright 2016, Tresys Technology, LLC
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
import sys
import logging

from PyQt5.QtCore import Qt, QSortFilterProxyModel, QStringListModel, QThread
from PyQt5.QtGui import QPalette, QTextCursor
from PyQt5.QtWidgets import QCompleter, QHeaderView, QMessageBox, QProgressDialog
from setools import NodeconQuery, NodeconIPVersion

from ..logtosignal import LogHandlerToSignal
from ..nodeconmodel import NodeconTableModel
from .analysistab import AnalysisTab
from .exception import TabFieldError
from .queryupdater import QueryResultsUpdater
from .workspace import load_checkboxes, load_lineedits, load_textedits, load_comboboxes, \
    save_checkboxes, save_lineedits, save_textedits, save_comboboxes


class NodeconQueryTab(AnalysisTab):

    """An nodecon query."""

    def __init__(self, parent, policy, perm_map):
        super(NodeconQueryTab, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.policy = policy
        self.query = NodeconQuery(policy)
        self.setupUi()

    def __del__(self):
        self.thread.quit()
        self.thread.wait(5000)
        logging.getLogger("setools.nodeconquery").removeHandler(self.handler)

    def setupUi(self):
        self.load_ui("apol/nodeconquery.ui")

        # set up user autocompletion
        user_completion_list = [str(u) for u in self.policy.users()]
        user_completer_model = QStringListModel(self)
        user_completer_model.setStringList(sorted(user_completion_list))
        self.user_completion = QCompleter()
        self.user_completion.setModel(user_completer_model)
        self.user.setCompleter(self.user_completion)

        # set up role autocompletion
        role_completion_list = [str(r) for r in self.policy.roles()]
        role_completer_model = QStringListModel(self)
        role_completer_model.setStringList(sorted(role_completion_list))
        self.role_completion = QCompleter()
        self.role_completion.setModel(role_completer_model)
        self.role.setCompleter(self.role_completion)

        # set up type autocompletion
        type_completion_list = [str(t) for t in self.policy.types()]
        type_completer_model = QStringListModel(self)
        type_completer_model.setStringList(sorted(type_completion_list))
        self.type_completion = QCompleter()
        self.type_completion.setModel(type_completer_model)
        self.type_.setCompleter(self.type_completion)

        # setup IP version
        # item 0 is empty string (in the .ui file)
        self.ip_version.insertItem(1, "IPv4", NodeconIPVersion.ipv4)
        self.ip_version.insertItem(2, "IPv6", NodeconIPVersion.ipv6)

        # setup indications of errors on source/target/default
        self.errors = set()
        self.orig_palette = self.type_.palette()
        self.error_palette = self.type_.palette()
        self.error_palette.setColor(QPalette.Base, Qt.red)
        self.clear_network_error()
        self.clear_user_error()
        self.clear_type_error()
        self.clear_role_error()
        self.clear_range_error()

        # set up results
        self.table_results_model = NodeconTableModel(self)
        self.sort_proxy = QSortFilterProxyModel(self)
        self.sort_proxy.setSourceModel(self.table_results_model)
        self.table_results.setModel(self.sort_proxy)
        self.table_results.sortByColumn(0, Qt.AscendingOrder)

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
        logging.getLogger("setools.nodeconquery").addHandler(self.handler)

        # Ensure settings are consistent with the initial .ui state
        self.criteria_frame.setHidden(not self.criteria_expander.isChecked())
        self.notes.setHidden(not self.notes_expander.isChecked())

        # Range criteria is available only if policy is MLS
        if not self.policy.mls:
            self.range_criteria.setEnabled(False)
            self.range_criteria.setToolTip("MLS is disabled in this policy.")
            self.range_.setToolTip("MLS is disabled in this policy.")
            self.range_exact.setToolTip("MLS is disabled in this policy.")
            self.range_overlap.setToolTip("MLS is disabled in this policy.")
            self.range_subset.setToolTip("MLS is disabled in this policy.")
            self.range_superset.setToolTip("MLS is disabled in this policy.")

        # connect signals
        self.buttonBox.clicked.connect(self.run)
        self.network.textEdited.connect(self.clear_network_error)
        self.network.editingFinished.connect(self.set_network)
        self.user.textEdited.connect(self.clear_user_error)
        self.user.editingFinished.connect(self.set_user)
        self.user_regex.toggled.connect(self.set_user_regex)
        self.role.textEdited.connect(self.clear_role_error)
        self.role.editingFinished.connect(self.set_role)
        self.role_regex.toggled.connect(self.set_role_regex)
        self.type_.textEdited.connect(self.clear_type_error)
        self.type_.editingFinished.connect(self.set_type)
        self.type_regex.toggled.connect(self.set_type_regex)
        self.range_.textEdited.connect(self.clear_range_error)
        self.range_.editingFinished.connect(self.set_range)

    #
    # Network criteria
    #
    def clear_network_error(self):
        self.clear_criteria_error(self.network, "Match the network.")

    def set_network(self):
        try:
            self.query.network = self.network.text()
        except Exception as ex:
            self.log.error("Network error: {0}".format(ex))
            self.set_criteria_error(self.network, ex)

    #
    # User criteria
    #
    def clear_user_error(self):
        self.clear_criteria_error(self.user, "Match the user of the context.")

    def set_user(self):
        try:
            self.query.user = self.user.text()
        except Exception as ex:
            self.log.error("Context user error: {0}".format(ex))
            self.set_criteria_error(self.user, ex)

    def set_user_regex(self, state):
        self.log.debug("Setting user_regex {0}".format(state))
        self.query.user_regex = state
        self.clear_user_error()
        self.set_user()

    #
    # Role criteria
    #
    def clear_role_error(self):
        self.clear_criteria_error(self.role, "Match the role of the context.")

    def set_role(self):
        try:
            self.query.role = self.role.text()
        except Exception as ex:
            self.log.error("Context role error: {0}".format(ex))
            self.set_criteria_error(self.role, ex)

    def set_role_regex(self, state):
        self.log.debug("Setting role_regex {0}".format(state))
        self.query.role_regex = state
        self.clear_role_error()
        self.set_role()

    #
    # Type criteria
    #
    def clear_type_error(self):
        self.clear_criteria_error(self.type_, "Match the type of the context.")

    def set_type(self):
        try:
            self.query.type_ = self.type_.text()
        except Exception as ex:
            self.log.error("Context type error: {0}".format(ex))
            self.set_criteria_error(self.type_, ex)

    def set_type_regex(self, state):
        self.log.debug("Setting type_regex {0}".format(state))
        self.query.type_regex = state
        self.clear_type_error()
        self.set_type()

    #
    # Range criteria
    #
    def clear_range_error(self):
        self.clear_criteria_error(self.range_, "Match the range of the context.")

    def set_range(self):
        try:
            self.query.range_ = self.range_.text()
        except Exception as ex:
            self.log.info("Context range error: " + str(ex))
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
        save_checkboxes(self, settings, ["criteria_expander", "notes_expander",
                                         "network_exact", "network_overlap",
                                         "user_regex", "role_regex", "type_regex", "range_exact",
                                         "range_overlap", "range_subset", "range_superset"])
        save_lineedits(self, settings, ["network", "user", "role", "type_", "range_"])
        save_comboboxes(self, settings, ["ip_version"])
        save_textedits(self, settings, ["notes"])
        return settings

    def load(self, settings):
        load_checkboxes(self, settings, ["criteria_expander", "notes_expander",
                                         "network_exact", "network_overlap",
                                         "user_regex", "role_regex", "type_regex", "range_exact",
                                         "range_overlap", "range_subset", "range_superset"])
        load_lineedits(self, settings, ["network", "user", "role", "type_", "range_"])
        load_comboboxes(self, settings, ["ip_version"])
        load_textedits(self, settings, ["notes"])

    #
    # Results runner
    #
    def run(self, button):
        # right now there is only one button.
        self.query.network_overlap = self.network_overlap.isChecked()
        self.query.ip_version = self.ip_version.currentData(Qt.UserRole)
        self.query.range_overlap = self.range_overlap.isChecked()
        self.query.range_subset = self.range_subset.isChecked()
        self.query.range_superset = self.range_superset.isChecked()

        # start processing
        self.busy.setLabelText("Processing query...")
        self.busy.show()
        self.raw_results.clear()
        self.thread.start()

    def update_complete(self, count):
        self.log.info("{0} nodecon statment(s) found.".format(count))

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
