# Copyright 2015-2016, Tresys Technology, LLC
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
from setools import TERuleQuery

from ..logtosignal import LogHandlerToSignal
from ..models import PermListModel, SEToolsListModel, invert_list_selection
from ..terulemodel import TERuleTableModel
from .analysistab import AnalysisTab
from .exception import TabFieldError
from .queryupdater import QueryResultsUpdater
from .workspace import load_checkboxes, load_lineedits, load_listviews, load_textedits, \
    save_checkboxes, save_lineedits, save_listviews, save_textedits


class TERuleQueryTab(AnalysisTab):

    """A Type Enforcement rule query."""

    def __init__(self, parent, policy, perm_map):
        super(TERuleQueryTab, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.policy = policy
        self.query = TERuleQuery(policy)
        self.setupUi()

    def __del__(self):
        self.thread.quit()
        self.thread.wait(5000)
        logging.getLogger("setools.terulequery").removeHandler(self.handler)

    def setupUi(self):
        self.load_ui("apol/terulequery.ui")

        # set up source/target autocompletion
        typeattr_completion_list = [str(t) for t in self.policy.types()]
        typeattr_completion_list.extend(str(a) for a in self.policy.typeattributes())
        typeattr_completer_model = QStringListModel(self)
        typeattr_completer_model.setStringList(sorted(typeattr_completion_list))
        self.typeattr_completion = QCompleter()
        self.typeattr_completion.setModel(typeattr_completer_model)
        self.source.setCompleter(self.typeattr_completion)
        self.target.setCompleter(self.typeattr_completion)

        # set up default autocompletion
        type_completion_list = [str(t) for t in self.policy.types()]
        type_completer_model = QStringListModel(self)
        type_completer_model.setStringList(sorted(type_completion_list))
        self.type_completion = QCompleter()
        self.type_completion.setModel(type_completer_model)
        self.default_type.setCompleter(self.type_completion)

        # setup indications of errors on source/target/default
        self.errors = set()
        self.orig_palette = self.source.palette()
        self.error_palette = self.source.palette()
        self.error_palette.setColor(QPalette.Base, Qt.red)
        self.clear_source_error()
        self.clear_target_error()
        self.clear_default_error()
        self.clear_xperm_error()

        # populate class list
        self.class_model = SEToolsListModel(self)
        self.class_model.item_list = sorted(self.policy.classes())
        self.tclass.setModel(self.class_model)

        # populate perm list
        self.perms_model = PermListModel(self, self.policy)
        self.perms.setModel(self.perms_model)

        # populate bool list
        self.bool_model = SEToolsListModel(self)
        self.bool_model.item_list = sorted(self.policy.bools())
        self.bool_criteria.setModel(self.bool_model)

        # set up results
        self.table_results_model = TERuleTableModel(self)
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
        logging.getLogger("setools.terulequery").addHandler(self.handler)

        # Ensure settings are consistent with the initial .ui state
        self.set_source_regex(self.source_regex.isChecked())
        self.set_target_regex(self.target_regex.isChecked())
        self.set_default_regex(self.default_regex.isChecked())
        self.toggle_xperm_criteria()
        self.criteria_frame.setHidden(not self.criteria_expander.isChecked())
        self.notes.setHidden(not self.notes_expander.isChecked())

        # connect signals
        self.buttonBox.clicked.connect(self.run)
        self.allowxperm.toggled.connect(self.toggle_xperm_criteria)
        self.auditallowxperm.toggled.connect(self.toggle_xperm_criteria)
        self.neverallowxperm.toggled.connect(self.toggle_xperm_criteria)
        self.dontauditxperm.toggled.connect(self.toggle_xperm_criteria)
        self.clear_ruletypes.clicked.connect(self.clear_all_ruletypes)
        self.all_ruletypes.clicked.connect(self.set_all_ruletypes)
        self.source.textEdited.connect(self.clear_source_error)
        self.source.editingFinished.connect(self.set_source)
        self.source_regex.toggled.connect(self.set_source_regex)
        self.target.textEdited.connect(self.clear_target_error)
        self.target.editingFinished.connect(self.set_target)
        self.target_regex.toggled.connect(self.set_target_regex)
        self.tclass.selectionModel().selectionChanged.connect(self.set_tclass)
        self.invert_class.clicked.connect(self.invert_tclass_selection)
        self.perms.selectionModel().selectionChanged.connect(self.set_perms)
        self.invert_perms.clicked.connect(self.invert_perms_selection)
        self.xperms.textEdited.connect(self.clear_xperm_error)
        self.xperms.editingFinished.connect(self.set_xperm)
        self.default_type.textEdited.connect(self.clear_default_error)
        self.default_type.editingFinished.connect(self.set_default_type)
        self.default_regex.toggled.connect(self.set_default_regex)
        self.bool_criteria.selectionModel().selectionChanged.connect(self.set_bools)

    #
    # Ruletype criteria
    #

    def _set_ruletypes(self, value):
        self.allow.setChecked(value)
        self.allowxperm.setChecked(value)
        self.auditallow.setChecked(value)
        self.auditallowxperm.setChecked(value)
        self.neverallow.setChecked(value)
        self.neverallowxperm.setChecked(value)
        self.dontaudit.setChecked(value)
        self.dontauditxperm.setChecked(value)
        self.type_transition.setChecked(value)
        self.type_member.setChecked(value)
        self.type_change.setChecked(value)

    def set_all_ruletypes(self):
        self._set_ruletypes(True)

    def clear_all_ruletypes(self):
        self._set_ruletypes(False)

    #
    # Source criteria
    #

    def clear_source_error(self):
        self.clear_criteria_error(self.source, "Match the source type/attribute of the rule.")

    def set_source(self):
        try:
            self.query.source = self.source.text()
        except Exception as ex:
            self.log.error("Source type/attribute error: {0}".format(ex))
            self.set_criteria_error(self.source, ex)

    def set_source_regex(self, state):
        self.log.debug("Setting source_regex {0}".format(state))
        self.query.source_regex = state
        self.clear_source_error()
        self.set_source()

    #
    # Target criteria
    #

    def clear_target_error(self):
        self.clear_criteria_error(self.target, "Match the target type/attribute of the rule.")

    def set_target(self):
        try:
            self.query.target = self.target.text()
        except Exception as ex:
            self.log.error("Target type/attribute error: {0}".format(ex))
            self.set_criteria_error(self.target, ex)

    def set_target_regex(self, state):
        self.log.debug("Setting target_regex {0}".format(state))
        self.query.target_regex = state
        self.clear_target_error()
        self.set_target()

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
    # Extended permission criteria
    #
    def toggle_xperm_criteria(self):
        mode = any((self.allowxperm.isChecked(),
                    self.auditallowxperm.isChecked(),
                    self.neverallowxperm.isChecked(),
                    self.dontauditxperm.isChecked()))

        self.xperms.setEnabled(mode)
        self.xperms_equal.setEnabled(mode)

    def clear_xperm_error(self):
        self.clear_criteria_error(self.xperms,
                                  "Match the extended permissions of the rule. "
                                  "Comma-separated permissions or ranges of permissions.")

    def set_xperm(self):
        xperms = []
        try:
            text = self.xperms.text()

            if text:
                for item in self.xperms.text().split(","):
                    rng = item.split("-")
                    if len(rng) == 2:
                        xperms.append((int(rng[0], base=16), int(rng[1], base=16)))
                    elif len(rng) == 1:
                        xperms.append((int(rng[0], base=16), int(rng[0], base=16)))
                    else:
                        raise ValueError("Enter an extended permission or extended permission "
                                         "range, e.g. 0x5411 or 0x8800-0x88ff.")

                self.query.xperms = xperms
            else:
                self.query.xperms = None

        except Exception as ex:
            self.log.error("Extended permissions error: {0}".format(ex))
            self.set_criteria_error(self.xperms, ex)

    #
    # Default criteria
    #

    def clear_default_error(self):
        self.clear_criteria_error(self.default_type, "Match the default type the rule.")

    def set_default_type(self):
        self.query.default_regex = self.default_regex.isChecked()

        try:
            self.query.default = self.default_type.text()
        except Exception as ex:
            self.log.error("Default type error: {0}".format(ex))
            self.set_criteria_error(self.default_type, ex)

    def set_default_regex(self, state):
        self.log.debug("Setting default_regex {0}".format(state))
        self.query.default_regex = state
        self.clear_default_error()
        self.set_default_type()

    #
    # Boolean criteria
    #

    def set_bools(self):
        selected_bools = []
        for index in self.bool_criteria.selectionModel().selectedIndexes():
            selected_bools.append(self.bool_model.data(index, Qt.UserRole))

        self.query.boolean = selected_bools

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
                                         "allow", "allowxperm",
                                         "auditallow", "auditallowxperm",
                                         "neverallow", "neverallowxperm",
                                         "dontaudit", "dontauditxperm",
                                         "type_transition", "type_change", "type_member",
                                         "source_indirect", "source_regex",
                                         "target_indirect", "target_regex",
                                         "perms_subset",
                                         "xperms_equal",
                                         "default_regex",
                                         "bools_equal"])
        save_lineedits(self, settings, ["source", "target", "xperms", "default_type"])
        save_listviews(self, settings, ["tclass", "perms", "bool_criteria"])
        save_textedits(self, settings, ["notes"])
        return settings

    def load(self, settings):
        load_checkboxes(self, settings, ["allow", "allowxperm",
                                         "auditallow", "auditallowxperm",
                                         "neverallow", "neverallowxperm",
                                         "dontaudit", "dontauditxperm",
                                         "type_transition", "type_change", "type_member",
                                         "criteria_expander", "notes_expander",
                                         "source_indirect", "source_regex",
                                         "target_indirect", "target_regex",
                                         "perms_subset",
                                         "xperms_equal",
                                         "default_regex",
                                         "bools_equal"])
        load_lineedits(self, settings, ["source", "target", "xperms", "default_type"])
        load_listviews(self, settings, ["tclass", "perms", "bool_criteria"])
        load_textedits(self, settings, ["notes"])

    #
    # Results runner
    #

    def run(self, button):
        # right now there is only one button.
        rule_types = []
        max_results = 0

        if self.allow.isChecked():
            rule_types.append("allow")
            max_results += self.policy.allow_count
        if self.allowxperm.isChecked():
            rule_types.append("allowxperm")
            max_results += self.policy.allowxperm_count
        if self.auditallow.isChecked():
            rule_types.append("auditallow")
            max_results += self.policy.auditallow_count
        if self.auditallowxperm.isChecked():
            rule_types.append("auditallowxperm")
            max_results += self.policy.auditallowxperm_count
        if self.neverallow.isChecked():
            rule_types.append("neverallow")
            max_results += self.policy.neverallow_count
        if self.neverallowxperm.isChecked():
            rule_types.append("neverallowxperm")
            max_results += self.policy.neverallowxperm_count
        if self.dontaudit.isChecked():
            rule_types.append("dontaudit")
            max_results += self.policy.dontaudit_count
        if self.dontauditxperm.isChecked():
            rule_types.append("dontauditxperm")
            max_results += self.policy.dontauditxperm_count
        if self.type_transition.isChecked():
            rule_types.append("type_transition")
            max_results += self.policy.type_transition_count
        if self.type_member.isChecked():
            rule_types.append("type_member")
            max_results += self.policy.type_member_count
        if self.type_change.isChecked():
            rule_types.append("type_change")
            max_results += self.policy.type_change_count

        self.query.ruletype = rule_types
        self.query.source_indirect = self.source_indirect.isChecked()
        self.query.target_indirect = self.target_indirect.isChecked()
        self.query.perms_subset = self.perms_subset.isChecked()
        self.query.boolean_equal = self.bools_equal.isChecked()

        # if query is broad, show warning.
        if not any((self.query.source, self.query.target, self.query.tclass, self.query.perms,
                    self.query.xperms, self.query.default, self.query.boolean)) \
                and max_results > 1000:

            reply = QMessageBox.question(
                self, "Continue?",
                "This is a broad query, estimated to return {0} results.  Continue?".
                format(max_results), QMessageBox.Yes | QMessageBox.No)

            if reply == QMessageBox.No:
                return

        # start processing
        self.busy.setLabelText("Processing query...")
        self.busy.show()
        self.raw_results.clear()
        self.thread.start()

    def update_complete(self, count):
        self.log.info("{0} type enforcement rule(s) found.".format(count))

        # update sizes/location of result displays
        if not self.busy.wasCanceled():
            self.busy.setLabelText("Resizing the result table's columns; GUI may be unresponsive")
            self.busy.repaint()
            self.table_results.resizeColumnsToContents()
            # If the permissions column width is too long, pull back
            # to a reasonable size
            header = self.table_results.horizontalHeader()
            if header.sectionSize(4) > 400:
                header.resizeSection(4, 400)

        if not self.busy.wasCanceled():
            self.busy.setLabelText("Resizing the result table's rows; GUI may be unresponsive")
            self.busy.repaint()
            self.table_results.resizeRowsToContents()

        if not self.busy.wasCanceled():
            self.busy.setLabelText("Moving the raw result to top; GUI may be unresponsive")
            self.busy.repaint()
            self.raw_results.moveCursor(QTextCursor.Start)

        self.busy.reset()
