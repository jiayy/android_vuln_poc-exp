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

from PyQt5.QtGui import QFont, QTextCursor
from PyQt5.QtWidgets import QDialog

from .widget import SEToolsWidget


class DetailsPopup(SEToolsWidget, QDialog):

    """A generic non-modal popup with a text field to write detailed info."""
    # TODO: make the font changes relative
    # instead of setting absolute values

    def __init__(self, parent, title=None):
        super(DetailsPopup, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.setupUi(title)

    def setupUi(self, title):
        self.load_ui("detail_popup.ui")

        if title:
            self.title = title

    @property
    def title(self):
        self.windowTitle(self)

    @title.setter
    def title(self, text):
        self.setWindowTitle(text)

    def append(self, text):
        self.contents.setFontWeight(QFont.Normal)
        self.contents.setFontPointSize(9)
        self.contents.append(text)

    def append_header(self, text):
        self.contents.setFontWeight(QFont.Black)
        self.contents.setFontPointSize(11)
        self.contents.append(text)

    def show(self):
        self.contents.moveCursor(QTextCursor.Start)
        super(DetailsPopup, self).show()
