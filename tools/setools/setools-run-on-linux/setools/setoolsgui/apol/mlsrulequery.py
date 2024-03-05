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
from setools import MLSRuleQuery

from ..logtosignal import LogHandlerToSignal
from ..models import SEToolsListModel, invert_list_selection
from ..mlsrulemodel import MLSRuleTableModel
from .analysistab import AnalysisTab
from .exception import TabFieldError
from .queryupdater import QueryResultsUpdater
from .workspace import load_checkboxes, load_lineedits, load_listviews, load_textedits, \
    save_checkboxes, save_lineedits, save_listviews, save_textedits


class MLSRuleQueryTab(AnalysisTab):

    """An MLS rule query."""

    def __init__(self, parent, policy, perm_map):
        super(MLSRuleQueryTab, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.policy = policy
        self.query = MLSRuleQuery(policy)
        self.setupUi()

    def __del__(self):
        self.thread.quit()
        self.thread.wait(5000)
        logging.getLogger("setools.mlsrulequery").removeHandler(self.handler)

    def setupUi(self):
        self.load_ui("apol/mlsrulequery.ui")

        # set up source/target autocompletion
        typeattr_completion_list = [str(t) for t in self.policy.types()]
        typeattr_completion_list.extend(str(a) for a in self.policy.typeattributes())
        typeattr_completer_model = QStringListModel(self)
        typeattr_completer_model.setStringList(sorted(typeattr_completion_list))
        self.typeattr_completion = QCompleter()
        self.typeattr_completion.setModel(typeattr_completer_model)
        self.source.setCompleter(self.typeattr_completion)
        self.target.setCompleter(self.typeattr_completion)

        # setup indications of errors on source/target/default
        self.errors = set()
        self.orig_palette = self.source.palette()
        self.error_palette = self.source.palette()
        self.error_palette.setColor(QPalette.Base, Qt.red)
        self.clear_source_error()
        self.clear_target_error()
        self.clear_default_error()

        # populate class list
        self.class_model = SEToolsListModel(self)
        self.class_model.item_list = sorted(self.policy.classes())
        self.tclass.setModel(self.class_model)

        # set up results
        self.table_results_model = MLSRuleTableModel(self)
        self.sort_proxy = QSortFilterProxyModel(self)
        self.sort_proxy.setSourceModel(self.table_results_model)
        self.table_results.setModel(self.sort_proxy)
        self.table_results.sortByColumn(1, Qt.AscendingOrder)

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
        logging.getLogger("setools.mlsrulequery").addHandler(self.handler)

        # Ensure settings are consistent with the initial .ui state
        self.set_source_regex(self.source_regex.isChecked())
        self.set_target_regex(self.target_regex.isChecked())
        self.criteria_frame.setHidden(not self.criteria_expander.isChecked())
        self.notes.setHidden(not self.notes_expander.isChecked())

        # connect signals
        self.buttonBox.clicked.connect(self.run)
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
        self.default_range.textEdited.connect(self.clear_default_error)
        self.default_range.editingFinished.connect(self.set_default_range)

    #
    # Ruletype criteria
    #

    def _set_ruletypes(self, value):
        self.range_transition.setChecked(value)

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

    def invert_tclass_selection(self):
        invert_list_selection(self.tclass.selectionModel())

    #
    # Default criteria
    #

    def clear_default_error(self):
        self.clear_criteria_error(self.default_range, "Match the default type the rule.")

    def set_default_range(self):
        try:
            self.query.default = self.default_range.text()
        except Exception as ex:
            self.log.error("Default range error: {0}".format(ex))
            self.set_criteria_error(self.default_range, ex)

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
                                         "range_transition",
                                         "source_indirect", "source_regex",
                                         "target_indirect", "target_regex"])
        save_lineedits(self, settings, ["source", "target", "default_range"])
        save_listviews(self, settings, ["tclass"])
        save_textedits(self, settings, ["notes"])
        return settings

    def load(self, settings):
        load_checkboxes(self, settings, ["criteria_expander", "notes_expander",
                                         "range_transition",
                                         "source_indirect", "source_regex",
                                         "target_indirect", "target_regex"])
        load_lineedits(self, settings, ["source", "target", "default_range"])
        load_listviews(self, settings, ["tclass"])
        load_textedits(self, settings, ["notes"])

    #
    # Results runner
    #

    def run(self, button):
        # right now there is only one button.

        self.query.ruletype = ['range_transition']
        self.query.source_indirect = self.source_indirect.isChecked()
        self.query.target_indirect = self.target_indirect.isChecked()

        # start processing
        self.busy.setLabelText("Processing query...")
        self.busy.show()
        self.raw_results.clear()
        self.thread.start()

    def update_complete(self, count):
        self.log.info("{0} MLS rule(s) found.".format(count))

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
