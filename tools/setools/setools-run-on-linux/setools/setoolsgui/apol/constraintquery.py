# Copyright 2015, Tresys Technology, LLC
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
from setools import ConstraintQuery

from ..logtosignal import LogHandlerToSignal
from ..models import PermListModel, SEToolsListModel, invert_list_selection
from ..constraintmodel import ConstraintTableModel
from .analysistab import AnalysisTab
from .exception import TabFieldError
from .queryupdater import QueryResultsUpdater
from .workspace import load_checkboxes, load_lineedits, load_listviews, load_textedits, \
    save_checkboxes, save_lineedits, save_listviews, save_textedits


class ConstraintQueryTab(AnalysisTab):

    """A constraint query."""

    def __init__(self, parent, policy, perm_map):
        super(ConstraintQueryTab, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.policy = policy
        self.query = ConstraintQuery(policy)
        self.setupUi()

    def __del__(self):
        self.thread.quit()
        self.thread.wait(5000)
        logging.getLogger("setools.constraintquery").removeHandler(self.handler)

    def setupUi(self):
        self.load_ui("apol/constraintquery.ui")

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

        # populate class list
        self.class_model = SEToolsListModel(self)
        self.class_model.item_list = sorted(self.policy.classes())
        self.tclass.setModel(self.class_model)

        # populate perm list
        self.perms_model = PermListModel(self, self.policy)
        self.perms.setModel(self.perms_model)

        # setup indications of errors
        self.errors = set()
        self.orig_palette = self.type_.palette()
        self.error_palette = self.type_.palette()
        self.error_palette.setColor(QPalette.Base, Qt.red)
        self.clear_user_error()
        self.clear_type_error()
        self.clear_role_error()

        # set up results
        self.table_results_model = ConstraintTableModel(self)
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
        logging.getLogger("setools.constraintquery").addHandler(self.handler)

        # Ensure settings are consistent with the initial .ui state
        self.set_user_regex(self.user_regex.isChecked())
        self.set_role_regex(self.role_regex.isChecked())
        self.set_type_regex(self.type_regex.isChecked())
        self.criteria_frame.setHidden(not self.criteria_expander.isChecked())
        self.notes.setHidden(not self.notes_expander.isChecked())

        # MLS constraints available only if policy is MLS
        if not self.policy.mls:
            self.mlsconstrain.setEnabled(False)
            self.mlsvalidatetrans.setEnabled(False)
            self.mlsconstrain.setToolTip("MLS is disabled in this policy.")
            self.mlsvalidatetrans.setToolTip("MLS is disabled in this policy.")

        # connect signals
        self.buttonBox.clicked.connect(self.run)
        self.clear_ruletypes.clicked.connect(self.clear_all_ruletypes)
        self.all_ruletypes.clicked.connect(self.set_all_ruletypes)
        self.user.textEdited.connect(self.clear_user_error)
        self.user.editingFinished.connect(self.set_user)
        self.user_regex.toggled.connect(self.set_user_regex)
        self.role.textEdited.connect(self.clear_role_error)
        self.role.editingFinished.connect(self.set_role)
        self.role_regex.toggled.connect(self.set_role_regex)
        self.type_.textEdited.connect(self.clear_type_error)
        self.type_.editingFinished.connect(self.set_type)
        self.type_regex.toggled.connect(self.set_type_regex)
        self.tclass.selectionModel().selectionChanged.connect(self.set_tclass)
        self.invert_class.clicked.connect(self.invert_tclass_selection)
        self.perms.selectionModel().selectionChanged.connect(self.set_perms)
        self.invert_perms.clicked.connect(self.invert_perms_selection)

    #
    # Ruletype criteria
    #
    def _set_ruletypes(self, value):
        self.constrain.setChecked(value)
        self.validatetrans.setChecked(value)

        if self.policy.mls:
            self.mlsconstrain.setChecked(value)
            self.mlsvalidatetrans.setChecked(value)

    def set_all_ruletypes(self):
        self._set_ruletypes(True)

    def clear_all_ruletypes(self):
        self._set_ruletypes(False)

    #
    # Class criteria
    #
    def set_tclass(self):
        selected_classes = []
        for index in self.tclass.selectionModel().selectedIndexes():
            selected_classes.append(self.class_model.data(index, Qt.UserRole))

        self.query.tclass = selected_classes
        self.perms_model.set_classes(selected_classes)

    def invert_tclass_selection(self):
        invert_list_selection(self.tclass.selectionModel())

    #
    # Permissions criteria
    #
    def set_perms(self):
        selected_perms = []
        for index in self.perms.selectionModel().selectedIndexes():
            selected_perms.append(self.perms_model.data(index, Qt.UserRole))

        self.query.perms = selected_perms

    def invert_perms_selection(self):
        invert_list_selection(self.perms.selectionModel())

    #
    # User criteria
    #
    def clear_user_error(self):
        self.clear_criteria_error(self.user,
                                  "Match constraints that have a user in the expression.")

    def set_user(self):
        try:
            self.query.user = self.user.text()
        except Exception as ex:
            self.log.error("User error: {0}".format(ex))
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
        self.clear_criteria_error(self.role,
                                  "Match constraints that have a role in the expression.")

    def set_role(self):
        try:
            self.query.role = self.role.text()
        except Exception as ex:
            self.log.error("Role error: {0}".format(ex))
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
        self.clear_criteria_error(self.type_,
                                  "Match constraints that have a type in the expression.")

    def set_type(self):
        try:
            self.query.type_ = self.type_.text()
        except Exception as ex:
            self.log.error("Type error: {0}".format(ex))
            self.set_criteria_error(self.type_, ex)

    def set_type_regex(self, state):
        self.log.debug("Setting type_regex {0}".format(state))
        self.query.type_regex = state
        self.clear_type_error()
        self.set_type()

    #
    # Save/Load tab
    #
    def save(self):
        """Return a dictionary of settings."""
        if self.errors:
            raise TabFieldError("Field(s) are in error: {0}".
                                format(" ".join(o.objectName() for o in self.errors)))

        settings = {}
        save_checkboxes(self, settings, ["criteria_expander", "notes_expander", "constrain",
                                         "mlsconstrain", "validatetrans", "mlsvalidatetrans",
                                         "user_regex", "role_regex", "type_regex", "perms_subset"])
        save_lineedits(self, settings, ["user", "role", "type_"])
        save_listviews(self, settings, ["tclass", "perms"])
        save_textedits(self, settings, ["notes"])
        return settings

    def load(self, settings):
        load_checkboxes(self, settings, ["criteria_expander", "notes_expander", "constrain",
                                         "mlsconstrain", "validatetrans", "mlsvalidatetrans",
                                         "user_regex", "role_regex", "type_regex", "perms_subset"])
        load_lineedits(self, settings, ["user", "role", "type_"])
        load_listviews(self, settings, ["tclass", "perms"])
        load_textedits(self, settings, ["notes"])

    #
    # Results runner
    #
    def run(self, button):
        # right now there is only one button.
        rule_types = []
        for mode in [self.constrain, self.mlsconstrain, self.validatetrans, self.mlsvalidatetrans]:
            if mode.isChecked():
                rule_types.append(mode.objectName())

        self.query.ruletype = rule_types
        self.query.perms_subset = self.perms_subset.isChecked()

        # start processing
        self.busy.setLabelText("Processing query...")
        self.busy.show()
        self.raw_results.clear()
        self.thread.start()

    def update_complete(self, count):
        self.log.info("{0} constraint(s) found.".format(count))

        # update sizes/location of result displays
        if not self.busy.wasCanceled():
            self.busy.setLabelText("Resizing the result table's columns; GUI may be unresponsive")
            self.busy.repaint()
            self.table_results.resizeColumnsToContents()
            # If the permissions or expression column widths are too long, pull back
            # to a reasonable size
            header = self.table_results.horizontalHeader()
            if header.sectionSize(2) > 400:
                header.resizeSection(2, 400)
            if header.sectionSize(3) > 400:
                header.resizeSection(3, 400)

        if not self.busy.wasCanceled():
            self.busy.setLabelText("Resizing the result table's rows; GUI may be unresponsive")
            self.busy.repaint()
            self.table_results.resizeRowsToContents()

        if not self.busy.wasCanceled():
            self.busy.setLabelText("Moving the raw result to top; GUI may be unresponsive")
            self.busy.repaint()
            self.raw_results.moveCursor(QTextCursor.Start)

        self.busy.reset()
