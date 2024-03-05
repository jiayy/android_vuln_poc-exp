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
from PyQt5.QtCore import Qt, QModelIndex
from PyQt5.QtGui import QKeySequence, QCursor
from PyQt5.QtWidgets import QAction, QApplication, QFileDialog, QMenu, QTreeWidget, \
    QTreeWidgetItemIterator


class SEToolsTreeWidget(QTreeWidget):

    """QTreeWidget class extended for SETools use."""

    def __init__(self, parent):
        super(SEToolsTreeWidget, self).__init__(parent)

        # set up right-click context menu
        self.copy_tree_action = QAction("Copy Tree...", self)
        self.menu = QMenu(self)
        self.menu.addAction(self.copy_tree_action)

        # connect signals
        self.copy_tree_action.triggered.connect(self.copy_tree)

    def contextMenuEvent(self, event):
        self.menu.popup(QCursor.pos())

    def copy_tree(self):
        """Copy the tree to the clipboard."""

        items = []
        inval_index = QModelIndex()
        it = QTreeWidgetItemIterator(self)
        prev_depth = 0
        while it.value():
            depth = 0
            item = it.value()
            parent = item.parent()
            while parent:
                depth += 1
                parent = parent.parent()

            if depth < prev_depth:
                items.extend(["  |" * depth, "\n"])

            if depth:
                items.extend(["  |" * depth, "--", item.text(0), "\n"])
            else:
                items.extend([item.text(0), "\n"])

            prev_depth = depth
            it += 1

        QApplication.clipboard().setText("".join(items))

    def event(self, e):
        if e == QKeySequence.Copy or e == QKeySequence.Cut:
            self.copy_tree()
            return True
        else:
            return super(SEToolsTreeWidget, self).event(e)
