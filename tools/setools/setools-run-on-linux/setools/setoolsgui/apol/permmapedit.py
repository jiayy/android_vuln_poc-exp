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
import copy

from PyQt5.QtCore import pyqtSignal, pyqtSlot, Qt
from PyQt5.QtGui import QPalette
from PyQt5.QtWidgets import QDialog, QFrame, QWidget

from ..models import SEToolsListModel
from ..widget import SEToolsWidget


class PermissionMapEditor(SEToolsWidget, QDialog):

    """
    A permission map editor.  This dialog has two versions,
    one for editing the weight/direction and another for
    including or excluding permissions in an analysis.

    Parameters:
    parent      The parent Qt widget
    edit        (bool) If true, the dialog will take
                the editor behavior.  If False, the dialog
                will take the enable/disable permission
                behavior.
    """

    class_toggle = pyqtSignal(bool)

    def __init__(self, parent, edit):
        super(PermissionMapEditor, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.parent = parent
        self.edit = edit
        self.setupUi()

    def setupUi(self):
        self.load_ui("apol/permmap_editor.ui")

        # set up class list
        self.class_model = SEToolsListModel(self)
        self.classes.setModel(self.class_model)

        # permission widgets
        self.widgets = []

        # set up editor mode
        self.enable_all.setHidden(self.edit)
        self.disable_all.setHidden(self.edit)

        # connect signals
        self.classes.selectionModel().selectionChanged.connect(self.class_selected)
        self.enable_all.clicked.connect(self.enable_all_perms)
        self.disable_all.clicked.connect(self.disable_all_perms)

    def show(self, perm_map):
        # keep an internal copy because the map is mutable
        # and this dialog may be canceled after some edits.
        self.perm_map = copy.deepcopy(perm_map)

        self.class_model.item_list = sorted(perm_map.classes())

        # clear class selection and mappings
        # since this widget will typically
        # be reused.
        self.classes.clearSelection()
        self._clear_mappings()
        self.enable_all.setToolTip(None)
        self.disable_all.setToolTip(None)

        if self.edit:
            self.setWindowTitle("{0} - Permission Map Editor - apol".format(self.perm_map))
        else:
            self.setWindowTitle("{0} - Permission Map Viewer - apol".format(self.perm_map))

        super(PermissionMapEditor, self).show()

    def accept(self):
        self.parent.apply_permmap(self.perm_map)
        super(PermissionMapEditor, self).accept()

    def class_selected(self):
        # the .ui is set to 1 selection
        for index in self.classes.selectionModel().selectedIndexes():
            class_name = self.class_model.data(index, Qt.DisplayRole)

        self.log.debug("Setting class to {0}".format(class_name))

        self.enable_all.setToolTip("Include all permissions in the {0} class.".format(class_name))
        self.disable_all.setToolTip("Exclude all permissions in the {0} class.".format(class_name))

        self._clear_mappings()

        # populate new mappings
        for perm in sorted(self.perm_map.perms(class_name)):
            # create permission mapping
            mapping = PermissionMapping(self, perm, self.edit)
            mapping.setAttribute(Qt.WA_DeleteOnClose)
            self.class_toggle.connect(mapping.enabled.setChecked)
            self.perm_mappings.addWidget(mapping)
            self.widgets.append(mapping)

            # add horizonal line
            line = QFrame(self)
            line.setFrameShape(QFrame.HLine)
            line.setFrameShadow(QFrame.Sunken)
            self.perm_mappings.addWidget(line)
            self.widgets.append(line)

    def enable_all_perms(self):
        self.class_toggle.emit(True)

    def disable_all_perms(self):
        self.class_toggle.emit(False)

    #
    # Internal functions
    #
    def _clear_mappings(self):
        # delete current mappings
        for mapping in self.widgets:
            mapping.close()

        self.widgets.clear()


index_to_setting = ["r", "w", "b", "n"]
index_to_word = ["Read", "Write", "Both", "None"]
setting_to_index = {"r": 0, "w": 1, "b": 2, "n": 3}


class PermissionMapping(SEToolsWidget, QWidget):

    """
    A widget representing mapping for a particular permission.
    This dialog has two versions, one for editing the weight/direction
    and another for including or excluding permissions in an analysis.

    Parameters:
    parent      The parent Qt widget
    edit        (bool) If true, the widget will take
                the editor behavior.  If False, the dialog
                will take the enable/disable permission
                behavior.
    """

    def __init__(self, parent, mapping, edit):
        super(PermissionMapping, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.parent = parent
        self.mapping = mapping
        self.edit = edit
        self.setupUi()

    def setupUi(self):
        self.load_ui("apol/permmapping.ui")

        self.permission.setText(str(self.mapping.perm))
        self.weight.setValue(self.mapping.weight)
        self.enabled.setChecked(self.mapping.enabled)

        if self.edit:
            self.weight.setToolTip("Set the information flow weight of {0}".format(
                self.mapping.perm))
            self.direction.setToolTip("Set the information flow direction of {0}".format(
                self.mapping.perm))
        else:
            self.enabled.setToolTip("Include or exclude {0} from the analysis.".format(
                self.mapping.perm))

        self.weight.setEnabled(self.edit)
        self.direction.setEnabled(self.edit)
        self.enabled.setHidden(self.edit)

        # setup color palettes for direction
        self.orig_palette = self.direction.palette()
        self.error_palette = self.direction.palette()
        self.error_palette.setColor(QPalette.Button, Qt.red)
        self.error_palette.setColor(QPalette.ButtonText, Qt.white)

        # setup direction
        self.direction.insertItems(0, index_to_word)
        if self.mapping.direction == 'u':
            # Temporarily add unmapped value to items
            self.direction.insertItem(len(index_to_word), "Unmapped")
            self.direction.setCurrentText("Unmapped")
            self.direction.setPalette(self.error_palette)
            self.unmapped = True
        else:
            self.direction.setCurrentIndex(setting_to_index[self.mapping.direction])
            self.unmapped = False

        # connect signals
        self.direction.currentIndexChanged.connect(self.set_direction)
        self.weight.valueChanged.connect(self.set_weight)
        self.enabled.toggled.connect(self.set_enabled)

    def set_direction(self, value):
        if self.unmapped:
            if value == "Unmapped":
                return

            # Remove unmapped item if setting the mapping.
            self.direction.removeItem(len(index_to_word))
            self.direction.setPalette(self.orig_palette)
            self.unmapped = False

        dir_ = index_to_setting[value]
        self.log.debug("Setting {0.class_}:{0.perm} direction to {1}".format(self.mapping, dir_))
        self.mapping.direction = dir_

    def set_weight(self, value):
        self.log.debug("Setting {0.class_}:{0.perm} weight to {1}".format(self.mapping, value))
        self.mapping.weight = int(value)

    def set_enabled(self, value):
        self.log.debug("Setting {0.class_}:{0.perm} enabled to {1}".format(self.mapping, value))
        self.mapping.enabled = value
