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
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import QAction, QListView, QMenu


class GetDetailsListView(QListView):

    """A QListView widget with more details context menu."""

    def __init__(self, parent):
        super(GetDetailsListView, self).__init__(parent)

        # set up right-click context menu
        self.get_detail = QAction("More details...", self)
        self.menu = QMenu(self)
        self.menu.addAction(self.get_detail)

    def contextMenuEvent(self, event):
        self.menu.popup(QCursor.pos())
