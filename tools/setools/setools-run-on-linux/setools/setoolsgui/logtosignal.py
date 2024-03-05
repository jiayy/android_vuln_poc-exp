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

from logging import Formatter, Handler, INFO
from PyQt5.QtCore import pyqtSignal, QObject


class LogHandlerToSignal(Handler, QObject):

    """
    A Python logging Handler that sends log messages over
    Qt signals.  By default the handler level is set to
    logging.INFO and only the message is signalled.

    Qt signals:
    message     (str) A message from the Python logging system.
    """

    message = pyqtSignal(str)

    def __init__(self):
        Handler.__init__(self)
        QObject.__init__(self)
        self.setLevel(INFO)
        self.setFormatter(Formatter('%(message)s'))

    def emit(self, record):
        msg = self.format(record)

        if msg:
            self.message.emit(msg)
