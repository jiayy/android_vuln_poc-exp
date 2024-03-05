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

from PyQt5.QtCore import Qt, QSortFilterProxyModel
from PyQt5.QtWidgets import QDialog

from ..models import SEToolsListModel
from ..widget import SEToolsWidget


class ExcludeTypes(SEToolsWidget, QDialog):

    """Dialog for choosing excluded types."""

    def __init__(self, parent, policy):
        super(ExcludeTypes, self).__init__(parent)
        self.log = logging.getLogger(__name__)
        self.parent = parent
        self.policy = policy
        self.initial_excluded_list = copy.copy(self.parent.query.exclude)
        self.setupUi()

    def setupUi(self):
        self.load_ui("apol/exclude_types.ui")

        # populate the attribute combo box:
        self.attr_model = SEToolsListModel(self)
        self.attr_model.item_list = [""] + sorted(self.policy.typeattributes())
        self.attr.setModel(self.attr_model)

        # populate the models:
        self.included_model = SEToolsListModel(self)
        self.included_model.item_list = [t for t in self.policy.types()
                                         if t not in self.initial_excluded_list]
        self.included_sort = FilterByAttributeProxy(self)
        self.included_sort.setSourceModel(self.included_model)
        self.included_sort.sort(0, Qt.AscendingOrder)
        self.included_types.setModel(self.included_sort)

        self.excluded_model = SEToolsListModel(self)
        self.excluded_model.item_list = self.initial_excluded_list
        self.excluded_sort = FilterByAttributeProxy(self)
        self.excluded_sort.setSourceModel(self.excluded_model)
        self.excluded_sort.sort(0, Qt.AscendingOrder)
        self.excluded_types.setModel(self.excluded_sort)

        # connect signals
        self.exclude_a_type.clicked.connect(self.exclude_clicked)
        self.include_a_type.clicked.connect(self.include_clicked)
        self.attr.currentIndexChanged.connect(self.set_attr_filter)

    def include_clicked(self):
        included_scroll_pos = self.included_types.verticalScrollBar().value()
        excluded_scroll_pos = self.excluded_types.verticalScrollBar().value()

        selected_types = []
        for index in self.excluded_types.selectionModel().selectedIndexes():
            source_index = self.excluded_sort.mapToSource(index)
            item = self.excluded_model.data(source_index, Qt.UserRole)
            self.included_model.append(item)
            selected_types.append(item)

        self.log.debug("Including {0}".format(selected_types))

        for item in selected_types:
            self.excluded_model.remove(item)

        self.included_types.verticalScrollBar().setValue(included_scroll_pos)
        self.excluded_types.verticalScrollBar().setValue(excluded_scroll_pos)

    def exclude_clicked(self):
        included_scroll_pos = self.included_types.verticalScrollBar().value()
        excluded_scroll_pos = self.excluded_types.verticalScrollBar().value()

        selected_types = []
        for index in self.included_types.selectionModel().selectedIndexes():
            source_index = self.included_sort.mapToSource(index)
            item = self.included_model.data(source_index, Qt.UserRole)
            self.excluded_model.append(item)
            selected_types.append(item)

        self.log.debug("Excluding {0}".format(selected_types))

        for item in selected_types:
            self.included_model.remove(item)

        self.included_types.verticalScrollBar().setValue(included_scroll_pos)
        self.excluded_types.verticalScrollBar().setValue(excluded_scroll_pos)

    def set_attr_filter(self, row):
        index = self.attr_model.index(row)
        attr = self.attr_model.data(index, Qt.UserRole)
        self.log.debug("Attribute set to {0!r}".format(attr))
        self.included_sort.attr = attr
        self.excluded_sort.attr = attr

    def accept(self):
        self.log.debug("Chosen for exclusion: {0!r}".format(self.excluded_model.item_list))

        self.parent.query.exclude = self.excluded_model.item_list
        super(ExcludeTypes, self).accept()


class FilterByAttributeProxy(QSortFilterProxyModel):

    """Filter a list of types by attribute membership."""

    _attr = None

    @property
    def attr(self):
        return self._attr

    @attr.setter
    def attr(self, value):
        self._attr = value
        self.invalidateFilter()

    def filterAcceptsRow(self, row, parent):
        if self.attr:
            source = self.sourceModel()
            index = source.index(row)
            item = source.data(index, Qt.UserRole)
            if item not in self.attr:
                return False

        return True
