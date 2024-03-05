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
import copy
from collections import defaultdict
from contextlib import suppress

from PyQt5.QtCore import pyqtSignal, Qt, QStringListModel, QThread
from PyQt5.QtGui import QPalette, QTextCursor
from PyQt5.QtWidgets import QCompleter, QHeaderView, QMessageBox, QProgressDialog, \
    QTreeWidgetItem
from setools import InfoFlowAnalysis
from setools.exception import UnmappedClass, UnmappedPermission

from ..logtosignal import LogHandlerToSignal
from .analysistab import AnalysisTab
from .exception import TabFieldError
from .excludetypes import ExcludeTypes
from .permmapedit import PermissionMapEditor
from .workspace import load_checkboxes, load_spinboxes, load_lineedits, load_textedits, \
    save_checkboxes, save_spinboxes, save_lineedits, save_textedits


class InfoFlowAnalysisTab(AnalysisTab):

    """An information flow analysis tab."""

    @property
    def perm_map(self):
        return self.query.perm_map

    @perm_map.setter
    def perm_map(self, pmap):
        # copy permission map to keep enabled/disabled
        # settings private to this map.
        perm_map = copy.deepcopy(pmap)

        # transfer enabled/disabled settings from
        # current permission map, to the new map
        for classname in self.query.perm_map.classes():
            for mapping in self.query.perm_map.perms(classname):
                with suppress(UnmappedClass, UnmappedPermission):
                    perm_map.mapping(classname, mapping.perm).enabled = mapping.enabled

        # apply updated permission map
        self.query.perm_map = perm_map

    def __init__(self, parent, policy, perm_map):
        super(InfoFlowAnalysisTab, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.policy = policy
        self.query = InfoFlowAnalysis(policy, perm_map)
        self.query.source = None
        self.query.target = None
        self.setupUi()

    def __del__(self):
        self.thread.quit()
        self.thread.wait(5000)
        logging.getLogger("setools.infoflow").removeHandler(self.handler)

    def setupUi(self):
        self.log.debug("Initializing UI.")
        self.load_ui("apol/infoflow.ui")

        # set up error message for missing perm map
        self.error_msg = QMessageBox(self)
        self.error_msg.setStandardButtons(QMessageBox.Ok)

        # set up perm map editor
        self.permmap_editor = PermissionMapEditor(self, False)

        # set up source/target autocompletion
        type_completion_list = [str(t) for t in self.policy.types()]
        type_completer_model = QStringListModel(self)
        type_completer_model.setStringList(sorted(type_completion_list))
        self.type_completion = QCompleter()
        self.type_completion.setModel(type_completer_model)
        self.source.setCompleter(self.type_completion)
        self.target.setCompleter(self.type_completion)

        # setup indications of errors on source/target/default
        self.errors = set()
        self.orig_palette = self.source.palette()
        self.error_palette = self.source.palette()
        self.error_palette.setColor(QPalette.Base, Qt.red)
        self.clear_source_error()
        self.clear_target_error()

        # set up processing thread
        self.thread = ResultsUpdater(self.query)
        self.thread.raw_line.connect(self.raw_results.appendPlainText)
        self.thread.finished.connect(self.update_complete)
        self.thread.flows.connect(self.reset_browser)

        # set up browser thread
        self.browser_thread = BrowserUpdater(self.query)
        self.browser_thread.flows.connect(self.add_browser_children)

        # create a "busy, please wait" dialog
        self.busy = QProgressDialog(self)
        self.busy.setModal(True)
        self.busy.setRange(0, 0)
        self.busy.setMinimumDuration(0)
        self.busy.setCancelButton(None)
        self.busy.reset()

        # update busy dialog from infoflow INFO logs
        self.handler = LogHandlerToSignal()
        self.handler.message.connect(self.busy.setLabelText)
        logging.getLogger("setools.infoflow").addHandler(self.handler)

        # Ensure settings are consistent with the initial .ui state
        self.max_path_length.setEnabled(self.all_paths.isChecked())
        self.source.setEnabled(not self.flows_in.isChecked())
        self.target.setEnabled(not self.flows_out.isChecked())
        self.criteria_frame.setHidden(not self.criteria_expander.isChecked())
        self.notes.setHidden(not self.notes_expander.isChecked())
        self.browser_tab.setEnabled(self.flows_in.isChecked() or self.flows_out.isChecked())

        # connect signals
        self.buttonBox.clicked.connect(self.run)
        self.source.textEdited.connect(self.clear_source_error)
        self.source.editingFinished.connect(self.set_source)
        self.target.textEdited.connect(self.clear_target_error)
        self.target.editingFinished.connect(self.set_target)
        self.all_paths.toggled.connect(self.all_paths_toggled)
        self.flows_in.toggled.connect(self.flows_in_toggled)
        self.flows_out.toggled.connect(self.flows_out_toggled)
        self.min_perm_weight.valueChanged.connect(self.set_min_weight)
        self.exclude_types.clicked.connect(self.choose_excluded_types)
        self.edit_permmap.clicked.connect(self.open_permmap_editor)
        self.browser.currentItemChanged.connect(self.browser_item_selected)

    #
    # Analysis mode
    #
    def all_paths_toggled(self, value):
        self.clear_source_error()
        self.clear_target_error()
        self.max_path_length.setEnabled(value)

    def flows_in_toggled(self, value):
        self.clear_source_error()
        self.clear_target_error()
        self.source.setEnabled(not value)
        self.limit_paths.setEnabled(not value)
        self.browser_tab.setEnabled(value)

    def flows_out_toggled(self, value):
        self.clear_source_error()
        self.clear_target_error()
        self.target.setEnabled(not value)
        self.limit_paths.setEnabled(not value)
        self.browser_tab.setEnabled(value)

    #
    # Source criteria
    #
    def clear_source_error(self):
        self.clear_criteria_error(self.source, "The source type of the analysis.")

    def set_source(self):
        try:
            # look up the type here, so invalid types can be caught immediately
            text = self.source.text()
            if text:
                self.query.source = self.policy.lookup_type(text)
            else:
                self.query.source = None
        except Exception as ex:
            self.log.error("Source type error: {0}".format(str(ex)))
            self.set_criteria_error(self.source, ex)

    #
    # Target criteria
    #
    def clear_target_error(self):
        self.clear_criteria_error(self.target, "The target type of the analysis.")

    def set_target(self):
        try:
            # look up the type here, so invalid types can be caught immediately
            text = self.target.text()
            if text:
                self.query.target = self.policy.lookup_type(text)
            else:
                self.query.target = None
        except Exception as ex:
            self.log.error("Target type error: {0}".format(str(ex)))
            self.set_criteria_error(self.target, ex)

    #
    # Options
    #
    def set_min_weight(self, value):
        self.query.min_weight = value

    def choose_excluded_types(self):
        chooser = ExcludeTypes(self, self.policy)
        chooser.show()

    def open_permmap_editor(self):
        self.permmap_editor.show(self.perm_map)

    def apply_permmap(self, pmap):
        # used only by permission map editor
        self.query.perm_map = pmap

    #
    # Save/Load tab
    #
    def save(self):
        """Return a dictionary of settings."""
        if self.errors:
            raise TabFieldError("Field(s) are in error: {0}".
                                format(" ".join(o.objectName() for o in self.errors)))

        settings = {}
        save_checkboxes(self, settings, ["criteria_expander", "notes_expander", "all_paths",
                                         "all_shortest_paths", "flows_in", "flows_out"])
        save_lineedits(self, settings, ["source", "target"])
        save_spinboxes(self, settings, ["max_path_length", "limit_paths", "min_perm_weight"])
        save_textedits(self, settings, ["notes"])

        settings["exclude"] = [str(t) for t in self.query.exclude]

        settings["exclude_perms"] = defaultdict(list)
        for mapping in self.perm_map:
            if not mapping.enabled:
                settings["exclude_perms"][mapping.class_].append(mapping.perm)

        return settings

    def load(self, settings):
        load_checkboxes(self, settings, ["criteria_expander", "notes_expander", "all_paths",
                                         "all_shortest_paths", "flows_in", "flows_out"])
        load_lineedits(self, settings, ["source", "target"])
        load_spinboxes(self, settings, ["max_path_length", "limit_paths", "min_perm_weight"])
        load_textedits(self, settings, ["notes"])

        try:
            self.query.exclude = settings["exclude"]
        except KeyError:
            self.log.warning("Excluded types criteria missing from settings file.")

        if "exclude_perms" not in settings:
            self.log.warning("Excluded permissions missing from settings file.")
        else:
            for mapping in self.perm_map:
                # iterate over the map so that any permission
                # not in the setting file's exclude list is enabled.
                try:
                    mapping.enabled = mapping.perm not in settings["exclude_perms"][mapping.class_]
                except KeyError:
                    mapping.enabled = True

    #
    # Infoflow browser
    #
    def _new_browser_item(self, type_, parent, rules=None, children=None):
        # build main item
        item = QTreeWidgetItem(parent if parent else self.browser)
        item.setText(0, str(type_))
        item.type_ = type_
        item.children = children if children else []
        item.rules = rules if rules else []
        item.child_populated = children is not None

        # add child items
        for child_type, child_rules in item.children:
            child_item = self._new_browser_item(child_type, item, rules=child_rules)
            item.addChild(child_item)

        item.setExpanded(children is not None)

        self.log.debug("Built item for {0} with {1} children and {2} rules".format(
                       type_, len(item.children), len(item.rules)))

        return item

    def reset_browser(self, root_type, out, children):
        self.log.debug("Resetting browser.")

        # clear results
        self.browser.clear()
        self.browser_details.clear()

        # save browser details independent
        # from main analysis UI settings
        self.browser_root_type = root_type
        self.browser_mode = out

        root = self._new_browser_item(self.browser_root_type, self.browser, children=children)

        self.browser.insertTopLevelItem(0, root)

    def browser_item_selected(self, current, previous):
        if not current:
            # browser is being reset
            return

        self.log.debug("{0} selected in browser.".format(current.type_))
        self.browser_details.clear()

        try:
            parent_type = current.parent().type_
        except AttributeError:
            # should only hit his on the root item
            pass
        else:
            self.browser_details.appendPlainText("Information flows {0} {1} {2}\n".format(
                current.parent().type_, "->" if self.browser_mode else "<-", current.type_))

            for rule in current.rules:
                self.browser_details.appendPlainText(rule)

            self.browser_details.moveCursor(QTextCursor.Start)

        if not current.child_populated:
            self.busy.setLabelText("Gathering additional browser details for {0}...".format(
                                   current.type_))
            self.busy.show()
            self.browser_thread.out = self.browser_mode
            self.browser_thread.type_ = current.type_
            self.browser_thread.start()

    def add_browser_children(self, children):
        item = self.browser.currentItem()
        item.children = children

        self.log.debug("Adding children for {0}".format(item.type_))

        for child_type, child_rules in item.children:
            child_item = self._new_browser_item(child_type, item, rules=child_rules)
            item.addChild(child_item)

        item.child_populated = True
        self.busy.reset()

    #
    # Results runner
    #
    def run(self, button):
        # right now there is only one button.
        fail = False
        if self.source.isEnabled() and not self.query.source:
            self.set_criteria_error(self.source, "A source type is required")
            fail = True

        if self.target.isEnabled() and not self.query.target:
            self.set_criteria_error(self.target, "A target type is required.")
            fail = True

        if not self.perm_map:
            self.log.critical("A permission map is required to begin the analysis.")
            self.error_msg.critical(self,
                                    "No permission map available.",
                                    "Please load a permission map to begin the analysis.")
            fail = True

        if fail:
            return

        for mode in [self.all_paths, self.all_shortest_paths, self.flows_in, self.flows_out]:
            if mode.isChecked():
                break

        self.query.mode = mode.objectName()
        self.query.max_path_len = self.max_path_length.value()
        self.query.limit = self.limit_paths.value()

        # start processing
        self.busy.setLabelText("Processing query...")
        self.busy.show()
        self.raw_results.clear()
        self.thread.start()

    def update_complete(self):
        if not self.busy.wasCanceled():
            self.busy.setLabelText("Moving the raw result to top; GUI may be unresponsive")
            self.busy.repaint()
            self.raw_results.moveCursor(QTextCursor.Start)

            if self.flows_in.isChecked() or self.flows_out.isChecked():
                # move to browser tab for flows in/out
                self.results_frame.setCurrentIndex(1)
            else:
                self.results_frame.setCurrentIndex(0)

        self.busy.reset()


class ResultsUpdater(QThread):

    """
    Thread for processing queries and updating result widgets.

    Parameters:
    query       The query object
    model       The model for the results

    Qt signals:
    raw_line    A string to be appended to the raw results.
    flows       (str, bool, list) Initial information for populating
                the flows browser.
    """

    raw_line = pyqtSignal(str)
    flows = pyqtSignal(str, bool, list)

    def __init__(self, query):
        super(ResultsUpdater, self).__init__()
        self.query = query
        self.log = logging.getLogger(__name__)

    def __del__(self):
        self.wait()

    def run(self):
        """Run the query and update results."""

        assert self.query.limit, "Code doesn't currently handle unlimited (limit=0) paths."
        self.out = self.query.mode == "flows_out"

        if self.query.mode == "all_paths":
            self.transitive(self.query.all_paths(self.query.source, self.query.target,
                                                 self.query.max_path_len))
        elif self.query.mode == "all_shortest_paths":
            self.transitive(self.query.all_shortest_paths(self.query.source, self.query.target))
        elif self.query.mode == "flows_out":
            self.direct(self.query.infoflows(self.query.source, out=self.out))
        else:  # flows_in
            self.direct(self.query.infoflows(self.query.target, out=self.out))

    def transitive(self, paths):
        pathnum = 0
        for pathnum, path in enumerate(paths, start=1):
            self.raw_line.emit("Flow {0}:".format(pathnum))
            for stepnum, step in enumerate(path, start=1):
                self.raw_line.emit("  Step {0}: {1} -> {2}".format(stepnum,
                                                                   step.source,
                                                                   step.target))

                for rule in sorted(step.rules):
                    self.raw_line.emit("    {0}".format(rule))

                self.raw_line.emit("")

            if QThread.currentThread().isInterruptionRequested() or (pathnum >= self.query.limit):
                break
            else:
                QThread.yieldCurrentThread()

            self.raw_line.emit("")

        self.raw_line.emit("{0} information flow path(s) found.\n".format(pathnum))
        self.log.info("{0} information flow path(s) found.".format(pathnum))

    def direct(self, flows):
        flownum = 0
        child_types = []
        for flownum, flow in enumerate(flows, start=1):
            self.raw_line.emit("Flow {0}: {1} -> {2}".format(flownum, flow.source, flow.target))
            for rule in sorted(flow.rules):
                self.raw_line.emit("    {0}".format(rule))

            self.raw_line.emit("")

            # Generate results for flow browser
            if self.out:
                child_types.append((flow.target, sorted(str(r) for r in flow.rules)))
            else:
                child_types.append((flow.source, sorted(str(r) for r in flow.rules)))

            if QThread.currentThread().isInterruptionRequested():
                break
            else:
                QThread.yieldCurrentThread()

        self.raw_line.emit("{0} information flow(s) found.\n".format(flownum))
        self.log.info("{0} information flow(s) found.".format(flownum))

        # Update browser:
        root_type = self.query.source if self.out else self.query.target
        self.flows.emit(str(root_type), self.out, sorted(child_types))


class BrowserUpdater(QThread):

    """
    Thread for processing additional analysis for the browser.

    Parameters:
    query       The query object
    model       The model for the results

    Qt signals:
    flows       A list of child types to render in the
                infoflows browser.
    """

    flows = pyqtSignal(list)

    def __init__(self, query):
        super(BrowserUpdater, self).__init__()
        self.query = query
        self.type_ = None
        self.out = None
        self.log = logging.getLogger(__name__)

    def __del__(self):
        self.wait()

    def run(self):
        flownum = 0
        child_types = []
        for flownum, flow in enumerate(self.query.infoflows(self.type_, out=self.out), start=1):
            # Generate results for flow browser
            if self.out:
                child_types.append((flow.target, sorted(str(r) for r in flow.rules)))
            else:
                child_types.append((flow.source, sorted(str(r) for r in flow.rules)))

            if QThread.currentThread().isInterruptionRequested():
                break
            else:
                QThread.yieldCurrentThread()

        self.log.debug("{0} additional information flow(s) found.".format(flownum))

        # Update browser:
        self.flows.emit(sorted(child_types))
