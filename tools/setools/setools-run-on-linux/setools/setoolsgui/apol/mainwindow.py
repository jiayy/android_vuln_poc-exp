# Copyright 2015-2016, Tresys Technology, LLC
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
import os
import sys
import stat
import logging
import json
from errno import ENOENT
from contextlib import suppress

import pkg_resources
from PyQt5.QtCore import pyqtSlot, Qt, QProcess
from PyQt5.QtWidgets import QApplication, QFileDialog, QLineEdit, QMainWindow, QMessageBox
from setools import __version__, PermissionMap, SELinuxPolicy

from ..widget import SEToolsWidget
from ..logtosignal import LogHandlerToSignal
from .chooseanalysis import ChooseAnalysis, tab_map
from .exception import TabFieldError
from .permmapedit import PermissionMapEditor
from .summary import SummaryTab


class ApolMainWindow(SEToolsWidget, QMainWindow):

    def __init__(self, filename):
        super(ApolMainWindow, self).__init__()
        self.log = logging.getLogger(__name__)
        self._permmap = None
        self._policy = None
        self.setupUi()

        self.load_permmap()

        if filename:
            self.load_policy(filename)

        if self._policy:
            self.create_new_analysis("Summary", SummaryTab)

        self.update_window_title()
        self.toggle_workspace_actions()

    def setupUi(self):
        self.load_ui("apol/apol.ui")

        self.tab_counter = 0

        # set up analysis menu
        self.chooser = ChooseAnalysis(self)

        # set up error message dialog
        self.error_msg = QMessageBox(self)
        self.error_msg.setStandardButtons(QMessageBox.Ok)

        # set up permission map editor
        self.permmap_editor = PermissionMapEditor(self, True)

        # set up tab name editor
        self.tab_editor = QLineEdit(self.AnalysisTabs)
        self.tab_editor.setWindowFlags(Qt.Popup)

        # configure tab bar context menu
        tabBar = self.AnalysisTabs.tabBar()
        tabBar.addAction(self.rename_tab_action)
        tabBar.addAction(self.close_tab_action)
        tabBar.setContextMenuPolicy(Qt.ActionsContextMenu)

        # capture INFO and higher Python messages from setools lib for status bar
        handler = LogHandlerToSignal()
        handler.message.connect(self.statusbar.showMessage)
        logging.getLogger("setools").addHandler(handler)
        logging.getLogger("setoolsgui").addHandler(handler)

        # set up help browser process
        self.help_process = QProcess()

        # connect signals
        self.open_policy.triggered.connect(self.select_policy)
        self.close_policy_action.triggered.connect(self.close_policy)
        self.open_permmap.triggered.connect(self.select_permmap)
        self.new_analysis.triggered.connect(self.choose_analysis)
        self.AnalysisTabs.currentChanged.connect(self.toggle_workspace_actions)
        self.AnalysisTabs.tabCloseRequested.connect(self.close_tab)
        self.AnalysisTabs.tabBarDoubleClicked.connect(self.tab_name_editor)
        self.tab_editor.editingFinished.connect(self.rename_tab)
        self.rename_tab_action.triggered.connect(self.rename_active_tab)
        self.close_tab_action.triggered.connect(self.close_active_tab)
        self.new_from_settings_action.triggered.connect(self.new_analysis_from_config)
        self.load_settings_action.triggered.connect(self.load_settings)
        self.save_settings_action.triggered.connect(self.save_settings)
        self.load_workspace_action.triggered.connect(self.load_workspace)
        self.save_workspace_action.triggered.connect(self.save_workspace)
        self.copy_action.triggered.connect(self.copy)
        self.cut_action.triggered.connect(self.cut)
        self.paste_action.triggered.connect(self.paste)
        self.edit_permmap_action.triggered.connect(self.edit_permmap)
        self.save_permmap_action.triggered.connect(self.save_permmap)
        self.about_apol_action.triggered.connect(self.about_apol)
        self.apol_help_action.triggered.connect(self.apol_help)

        self.show()

    def update_window_title(self):
        if self._policy:
            self.setWindowTitle("{0} - apol".format(self._policy))
        else:
            self.setWindowTitle("apol")

    #
    # Policy handling
    #
    def select_policy(self):
        old_policy = self._policy

        if old_policy and self.AnalysisTabs.count() > 0:
            reply = QMessageBox.question(
                self, "Continue?",
                "Loading a policy will close all existing analyses.  Continue?",
                QMessageBox.Yes | QMessageBox.No)

            if reply == QMessageBox.No:
                return

        filename = QFileDialog.getOpenFileName(self, "Open policy file", ".",
                                               "SELinux Policies (policy.* sepolicy);;"
                                               "All Files (*)")[0]
        if filename:
            self.load_policy(filename)

        if self._policy != old_policy:
            # policy loading succeeded, clear any
            # existing tabs
            self.AnalysisTabs.clear()
            self.create_new_analysis("Summary", SummaryTab)

    def load_policy(self, filename):
        try:
            self._policy = SELinuxPolicy(filename)
        except Exception as ex:
            self.log.critical("Failed to load policy \"{0}\"".format(filename))
            self.error_msg.critical(self, "Policy loading error", str(ex))
        else:
            self.update_window_title()
            self.toggle_workspace_actions()

            if self._permmap:
                self._permmap.map_policy(self._policy)
                self.apply_permmap()

    def close_policy(self):
        if self.AnalysisTabs.count() > 0:
            reply = QMessageBox.question(
                self, "Continue?",
                "Loading a policy will close all existing analyses.  Continue?",
                QMessageBox.Yes | QMessageBox.No)

            if reply == QMessageBox.No:
                return

        self.AnalysisTabs.clear()
        self._policy = None
        self.update_window_title()
        self.toggle_workspace_actions()

    #
    # Permission map handling
    #
    def select_permmap(self):
        filename = QFileDialog.getOpenFileName(self, "Open permission map file", ".")[0]
        if filename:
            self.load_permmap(filename)

    def load_permmap(self, filename=None):
        try:
            self._permmap = PermissionMap(filename)
        except Exception as ex:
            self.log.critical("Failed to load default permission map: {0}".format(ex))
            self.error_msg.critical(self, "Permission map loading error", str(ex))
        else:
            if self._policy:
                self._permmap.map_policy(self._policy)
                self.apply_permmap()

    def edit_permmap(self):
        if not self._permmap:
            self.error_msg.critical(self, "No open permission map",
                                    "Cannot edit permission map. Please open a map first.")
            self.select_permmap()

        # in case user cancels out of
        # choosing a permmap, recheck
        if self._permmap:
            self.permmap_editor.show(self._permmap)

    def apply_permmap(self, perm_map=None):
        if perm_map:
            self._permmap = perm_map

        for index in range(self.AnalysisTabs.count()):
            tab = self.AnalysisTabs.widget(index)
            self.log.debug("Updating permmap in tab {0} ({1}: \"{2}\")".format(
                           index, tab, tab.objectName()))
            tab.perm_map = self._permmap

    def save_permmap(self):
        path = str(self._permmap) if self._permmap else "perm_map"
        filename = QFileDialog.getSaveFileName(self, "Save permission map file", path)[0]
        if filename:
            try:
                self._permmap.save(filename)
            except Exception as ex:
                self.log.critical("Failed to save permission map: {0}".format(ex))
                self.error_msg.critical(self, "Permission map saving error", str(ex))

    #
    # Analysis tab handling
    #
    def choose_analysis(self):
        if not self._policy:
            self.error_msg.critical(self, "No open policy",
                                    "Cannot start a new analysis. Please open a policy first.")

            self.select_policy()

        if self._policy:
            # this check of self._policy is here in case someone
            # tries to start an analysis with no policy open, but then
            # cancels out of the policy file chooser or there is an
            # error opening the policy file.
            self.chooser.show(self._policy.mls)

    def create_new_analysis(self, tabtitle, tabclass):
        self.tab_counter += 1
        counted_name = "{0}: {1}".format(self.tab_counter, tabtitle)

        newanalysis = tabclass(self, self._policy, self._permmap)
        newanalysis.setAttribute(Qt.WA_DeleteOnClose)
        newanalysis.setObjectName(counted_name)

        index = self.AnalysisTabs.addTab(newanalysis, counted_name)
        self.AnalysisTabs.setTabToolTip(index, tabtitle)
        self.AnalysisTabs.setCurrentIndex(index)
        return index

    def tab_name_editor(self, index):
        if index >= 0:
            tab_area = self.AnalysisTabs.tabBar().tabRect(index)
            self.tab_editor.move(self.AnalysisTabs.mapToGlobal(tab_area.topLeft()))
            self.tab_editor.setText(self.AnalysisTabs.tabText(index))
            self.tab_editor.selectAll()
            self.tab_editor.show()
            self.tab_editor.setFocus()

    def close_active_tab(self):
        """Close the active tab. This is called from the context menu."""
        index = self.AnalysisTabs.currentIndex()
        if index >= 0:
            self.close_tab(index)

    def rename_active_tab(self):
        """Rename the active tab."""
        index = self.AnalysisTabs.currentIndex()
        if index >= 0:
            self.tab_name_editor(index)

    def close_tab(self, index):
        """Close a tab specified by index."""
        widget = self.AnalysisTabs.widget(index)
        widget.close()
        self.AnalysisTabs.removeTab(index)

    def rename_tab(self):
        # this should never be negative since the editor is modal
        index = self.AnalysisTabs.currentIndex()
        tab = self.AnalysisTabs.widget(index)
        title = self.tab_editor.text()

        self.tab_editor.hide()

        self.AnalysisTabs.setTabText(index, title)
        tab.setObjectName(title)

    #
    # Workspace actions
    #
    def toggle_workspace_actions(self, index=-1):
        """
        Enable or disable workspace actions depending on
        how many tabs are open and if a policy is open.

        This is a slot for the QTabWidget.currentChanged()
        signal, though index is ignored.
        """
        open_tabs = self.AnalysisTabs.count() > 0
        open_policy = self._policy is not None

        self.log.debug("{0} actions requiring an open policy.".
                       format("Enabling" if open_policy else "Disabling"))
        self.log.debug("{0} actions requiring open tabs.".
                       format("Enabling" if open_tabs else "Disabling"))
        self.save_settings_action.setEnabled(open_tabs)
        self.save_workspace_action.setEnabled(open_tabs)
        self.new_analysis.setEnabled(open_policy)
        self.new_from_settings_action.setEnabled(open_policy)
        self.load_settings_action.setEnabled(open_tabs)

    def _get_settings(self, index=None):
        """Return a dictionary with the settings of the tab at the specified index."""
        if index is None:
            index = self.AnalysisTabs.currentIndex()

        assert index >= 0, "Tab index is negative in _get_settings.  This is an SETools bug."
        tab = self.AnalysisTabs.widget(index)

        settings = tab.save()

        # add the tab info to the settings.
        settings["__title__"] = self.AnalysisTabs.tabText(index)
        settings["__tab__"] = type(tab).__name__

        return settings

    def _put_settings(self, settings, index=None):
        """Load the settings into the specified tab."""

        if index is None:
            index = self.AnalysisTabs.currentIndex()

        assert index >= 0, "Tab index is negative in _put_settings.  This is an SETools bug."
        tab = self.AnalysisTabs.widget(index)

        if settings["__tab__"] != type(tab).__name__:
            raise TypeError("The current tab ({0}) does not match the tab in the settings file "
                            "({1}).".format(type(tab).__name__, settings["__tab__"]))

        try:
            self.AnalysisTabs.setTabText(index, str(settings["__title__"]))
        except KeyError:
            self.log.warning("Settings file does not have a title setting.")

        tab.load(settings)

    def load_settings(self, new=False):
        filename = QFileDialog.getOpenFileName(self, "Open settings file", ".",
                                               "Apol Tab Settings File (*.apolt);;"
                                               "All Files (*)")[0]
        if not filename:
            return

        try:
            with open(filename, "r") as fd:
                settings = json.load(fd)
        except ValueError as ex:
            self.log.critical("Invalid settings file \"{0}\"".format(filename))
            self.error_msg.critical(self, "Failed to load settings",
                                    "Invalid settings file: \"{0}\"".format(filename))
            return
        except OSError as ex:
            self.log.critical("Unable to load settings file \"{0.filename}\": {0.strerror}".
                              format(ex))
            self.error_msg.critical(self, "Failed to load settings",
                                    "Failed to load \"{0.filename}\": {0.strerror}".format(ex))
            return
        except Exception as ex:
            self.log.critical("Unable to load settings file \"{0}\": {1}".format(filename, ex))
            self.error_msg.critical(self, "Failed to load settings", str(ex))
            return

        self.log.info("Loading analysis settings from \"{0}\"".format(filename))

        if new:
            try:
                tabclass = tab_map[settings["__tab__"]]
            except KeyError:
                self.log.critical("Missing analysis type in \"{0}\"".format(filename))
                self.error_msg.critical(self, "Failed to load settings",
                                        "The type of analysis is missing in the settings file.")
                return

            # The tab title will be set by _put_settings.
            index = self.create_new_analysis("Tab", tabclass)
        else:
            index = None

        try:
            self._put_settings(settings, index)
        except Exception as ex:
            self.log.critical("Error loading settings file \"{0}\": {1}".format(filename, ex))
            self.error_msg.critical(self, "Failed to load settings",
                                    "Error loading settings file \"{0}\":\n\n{1}".
                                    format(filename, ex))
        else:
            self.log.info("Successfully loaded analysis settings from \"{0}\"".format(filename))

    def new_analysis_from_config(self):
        self.load_settings(new=True)

    def save_settings(self):
        try:
            settings = self._get_settings()

        except TabFieldError as ex:
            self.log.critical("Errors in the query prevent saving the settings. {0}".format(ex))
            self.error_msg.critical(self, "Unable to save settings",
                                    "Please resolve errors in the tab before saving the settings."
                                    )
            return

        filename = QFileDialog.getSaveFileName(self, "Save analysis tab settings", "analysis.apolt",
                                               "Apol Tab Settings File (*.apolt);;"
                                               "All Files (*)")[0]

        if not filename:
            return

        try:
            with open(filename, "w") as fd:
                json.dump(settings, fd, indent=1)
        except OSError as ex:
            self.log.critical("Unable to save settings file \"{0.filename}\": {0.strerror}".
                              format(ex))
            self.error_msg.critical(self, "Failed to save settings",
                                    "Failed to save \"{0.filename}\": {0.strerror}".format(ex))
        except Exception as ex:
            self.log.critical("Unable to save settings file \"{0}\": {1}".format(filename, ex))
            self.error_msg.critical(self, "Failed to save settings", str(ex))
        else:
            self.log.info("Successfully saved settings file \"{0}\"".format(filename))

    def load_workspace(self):
        # 1. if number of tabs > 0, check if we really want to do this
        if self.AnalysisTabs.count() > 0:
            reply = QMessageBox.question(
                self, "Continue?",
                "Loading a workspace will close all existing analyses.  Continue?",
                QMessageBox.Yes | QMessageBox.No)

            if reply == QMessageBox.No:
                return

        # 2. try to load the workspace file, if we fail, bail
        filename = QFileDialog.getOpenFileName(self, "Open workspace file", ".",
                                               "Apol Workspace Files (*.apolw);;"
                                               "All Files (*)")[0]

        if not filename:
            return

        try:
            with open(filename, "r") as fd:
                workspace = json.load(fd)
        except ValueError as ex:
            self.log.critical("Invalid workspace file \"{0}\"".format(filename))
            self.error_msg.critical(self, "Failed to load workspace",
                                    "Invalid workspace file: \"{0}\"".format(filename))
            return
        except OSError as ex:
            self.log.critical("Unable to load workspace file \"{0.filename}\": {0.strerror}".
                              format(ex))
            self.error_msg.critical(self, "Failed to load workspace",
                                    "Failed to load \"{0.filename}\": {0.strerror}".format(ex))
            return
        except Exception as ex:
            self.log.critical("Unable to load workspace file \"{0}\": {1}".format(filename, ex))
            self.error_msg.critical(self, "Failed to load workspace", str(ex))
            return

        # 3. close all tabs.  Explicitly do this to avoid the question
        #    about closing the policy with tabs open.
        self.AnalysisTabs.clear()

        # 4. close policy
        self.close_policy()

        # 5. try to open the specified policy, if we fail, bail.  Note:
        #    handling exceptions from the policy load is done inside
        #    the load_policy function, so only the KeyError needs to be caught here
        try:
            self.load_policy(workspace["__policy__"])
        except KeyError:
            self.log.critical("Missing policy in workspace file \"{0}\"".format(filename))
            self.error_msg.critical(self, "Missing policy in workspace file \"{0}\"".
                                    format(filename))

        if self._policy is None:
            self.log.critical("The policy could not be loaded in workspace file \"{0}\"".
                              format(filename))
            self.error_msg.critical(self, "The policy could not be loaded in workspace file \"{0}\""
                                    ". Aborting workspace load.".format(filename))
            return

        # 6. try to open the specified perm map, if we fail,
        #    tell the user we will continue with the default map; load the default map
        #    Note: handling exceptions from the map load is done inside
        #    the load_permmap function, so only the KeyError needs to be caught here
        try:
            self.load_permmap(workspace["__permmap__"])
        except KeyError:
            self.log.warning("Missing permission map in workspace file \"{0}\"".format(filename))
            self.error_msg.warning(self, "Missing permission map setting.",
                                   "Missing permission map in workspace file \"{0}\"".
                                   format(filename))

        if self._permmap is None:
            self.error_msg.information(self, "Loading default permission map.",
                                       "The default permisison map will be loaded.")
            self.load_permmap()

        # 7. try to open all tabs and apply settings.  Record any errors
        try:
            tab_list = list(workspace["__tabs__"])
        except KeyError:
            self.log.critical("Missing tab list in workspace file \"{0}\"".format(filename))
            self.error_msg.critical(self, "Failed to load workspace",
                                    "The workspace file is missing the tab list.  Aborting.")
            return
        except TypeError:
            self.log.critical("Invalid tab list in workspace file.")
            self.error_msg.critical(self, "Failed to load workspace",
                                    "The tab count is invalid.  Aborting.")
            return

        loading_errors = []
        for i, settings in enumerate(tab_list):
            try:
                tabclass = tab_map[settings["__tab__"]]
            except KeyError:
                error_str = "Missing analysis type for tab {0}. Skipping this tab.".format(i)
                self.log.error(error_str)
                loading_errors.append(error_str)
                continue

            # The tab title will be set by _put_settings.
            index = self.create_new_analysis("Tab", tabclass)

            try:
                self._put_settings(settings, index)
            except Exception as ex:
                error_str = "Error loading settings for tab {0}: {1}".format(i, ex)
                self.log.error(error_str)
                loading_errors.append(error_str)

        self.log.info("Completed loading workspace from \"{0}\"".format(filename))

        # 8. if there are any errors, open a dialog with the
        #    complete list of tab errors
        if loading_errors:
            self.error_msg.warning(self, "Errors while loading workspace:",
                                   "There were errors while loading the workspace:\n\n{0}".
                                   format("\n\n".join(loading_errors)))

    def save_workspace(self):
        workspace = {}
        save_errors = []

        workspace["__policy__"] = os.path.abspath(str(self._policy))
        workspace["__permmap__"] = os.path.abspath(str(self._permmap))
        workspace["__tabs__"] = []

        for index in range(self.AnalysisTabs.count()):
            tab = self.AnalysisTabs.widget(index)

            try:
                settings = tab.save()
            except TabFieldError as ex:
                tab_name = self.AnalysisTabs.tabText(index)
                save_errors.append(tab_name)
                self.log.error("Error: tab \"{0}\": {1}".format(tab_name, str(ex)))
            else:
                # add the tab info to the settings.
                settings["__title__"] = self.AnalysisTabs.tabText(index)
                settings["__tab__"] = type(tab).__name__

                workspace["__tabs__"].append(settings)

        if save_errors:
            self.log.critical("Errors in tabs prevent saving the workspace.")
            self.error_msg.critical(self, "Unable to save workspace",
                                    "Please resolve errors in the following tabs before saving the"
                                    " workspace:\n\n{0}".format("\n".join(save_errors)))
            return

        filename = QFileDialog.getSaveFileName(self, "Save analysis workspace", "workspace.apolw",
                                               "Apol Workspace Files (*.apolw);;"
                                               "All Files (*)")[0]

        if not filename:
            return

        with open(filename, "w") as fd:
            json.dump(workspace, fd, indent=1)

    #
    # Edit actions
    #
    def copy(self):
        """Copy text from the currently-focused widget."""
        with suppress(AttributeError):
            QApplication.instance().focusWidget().copy()

    def cut(self):
        """Cut text from the currently-focused widget."""
        with suppress(AttributeError):
            QApplication.instance().focusWidget().cut()

    def paste(self):
        """Paste text into the currently-focused widget."""
        with suppress(AttributeError):
            QApplication.instance().focusWidget().paste()

    #
    # Help actions
    #
    def about_apol(self):
        QMessageBox.about(self, "About Apol", "Version {0}<br>"
                          "Apol is a graphical SELinux policy analysis tool and part of "
                          "<a href=\"https://github.com/SELinuxProject/setools/wiki\">"
                          "SETools</a>.<p>"
                          "Copyright (C) 2015-2016, Tresys Technology<p>"
                          "Copyright (C) 2016, Chris PeBenito <pebenito@ieee.org>".
                          format(__version__))

    def apol_help(self):
        """Open the main help window."""
        if self.help_process.state() != QProcess.NotRunning:
            return

        distro = pkg_resources.get_distribution("setools")
        helpfile = "{0}/setoolsgui/apol/apol.qhc".format(distro.location)

        self.log.debug("Starting assistant with help file {0}".format(helpfile))
        self.help_process.start("assistant",
                                ["-collectionFile", helpfile, "-showUrl",
                                 "qthelp://com.github.selinuxproject.setools/doc/index.html",
                                 "-show", "contents", "-enableRemoteControl"])

    @pyqtSlot(str)
    def set_help(self, location):
        """Set the help window to the specified document."""
        if self.help_process.state() == QProcess.NotStarted:
            self.apol_help()
            if not self.help_process.waitForStarted():
                self.log.warning("Timed out waiting for Qt assistant to start.")
                return
        elif self.help_process.state() == QProcess.Starting:
            if not self.help_process.waitForStarted():
                self.log.warning("Timed out waiting for Qt assistant to start.")
                return

        self.help_process.write("setSource qthelp://com.github.selinuxproject.setools/doc/{0}\n".
                                format(location))
