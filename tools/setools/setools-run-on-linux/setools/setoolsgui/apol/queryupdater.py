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
from PyQt5.QtCore import pyqtSignal, QObject, QThread


class QueryResultsUpdater(QObject):

    """
    Thread for processing basic queries and updating result widgets.

    Parameters:
    query       The query object
    model       The model for the results

    Qt signals:
    finished    (int) The update has completed, with the number of results.
    raw_line    (str) A string to be appended to the raw results.
    """

    finished = pyqtSignal(int)
    raw_line = pyqtSignal(str)

    def __init__(self, query, model):
        super(QueryResultsUpdater, self).__init__()
        self.query = query
        self.model = model

    def update(self):
        """Run the query and update results."""
        self.model.beginResetModel()

        results = []
        counter = 0

        for counter, item in enumerate(self.query.results(), start=1):
            results.append(item)

            self.raw_line.emit(str(item))

            if QThread.currentThread().isInterruptionRequested():
                break
            elif not counter % 10:
                # yield execution every 10 rules
                QThread.yieldCurrentThread()

        self.model.resultlist = results
        self.model.endResetModel()

        self.finished.emit(counter)
