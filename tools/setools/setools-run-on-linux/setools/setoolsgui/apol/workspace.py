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
import re
import logging

import setools


from PyQt5.QtCore import Qt, QItemSelectionModel


def save_checkboxes(tab, settings, checkboxes):
    """
    Save settings from the checkable buttons (e.g. QCheckbox) in the tab.

    Parameters:
    tab         The tab object.
    settings    The dictionary of settings.  This will be mutated.
    checkboxes  A list of attribute names (str) of buttons in the tab.
    """

    for entry in checkboxes:
        checkbox = getattr(tab, entry)
        settings[entry] = checkbox.isChecked()


def load_checkboxes(tab, settings, checkboxes):
    """
    Load settings into the checkable buttons (e.g. QCheckbox) in the tab.

    Parameters:
    tab         The tab object.
    settings    The dictionary of settings.
    checkboxes  A list of attribute names (str) of buttons in the tab.
    """

    log = logging.getLogger(__name__)

    # next set options
    for entry in checkboxes:
        checkbox = getattr(tab, entry)

        try:
            checkbox.setChecked(bool(settings[entry]))
        except KeyError:
            log.warning("{0} option missing from settings file.".format(entry))


def save_lineedits(tab, settings, lines):
    """
    Save settings into the QLineEdit(s) in the tab.

    Parameters:
    tab         The tab object.
    settings    The dictionary of settings.  This will be mutated.
    lines       A list of attribute names (str) of QLineEdits in the tab.
    """

    # set line edits
    for entry in lines:
        lineedit = getattr(tab, entry)
        settings[entry] = lineedit.text()


def load_lineedits(tab, settings, lines):
    """
    Load settings into the QLineEdit(s) in the tab.

    Parameters:
    tab         The tab object.
    settings    The dictionary of settings.
    lines       A list of attribute names (str) of QLineEdits in the tab.
    """

    log = logging.getLogger(__name__)

    # set line edits
    for entry in lines:
        lineedit = getattr(tab, entry)

        try:
            lineedit.setText(str(settings[entry]))
        except KeyError:
            log.warning("{0} criteria missing from settings file.".format(entry))


def save_textedits(tab, settings, edits):
    """
    Save settings into the QTextEdit(s) in the tab.

    Parameters:
    tab         The tab object.
    settings    The dictionary of settings.  This will be mutated.
    edits       A list of attribute names (str) of QTextEdits in the tab.
    """

    # set line edits
    for entry in edits:
        textedit = getattr(tab, entry)
        settings[entry] = textedit.toPlainText()


def load_textedits(tab, settings, edits):
    """
    Load settings into the QTextEdit(s) in the tab.

    Parameters:
    tab         The tab object.
    settings    The dictionary of settings.
    edits       A list of attribute names (str) of QTextEdits in the tab.
    """

    log = logging.getLogger(__name__)

    # set line edits
    for entry in edits:
        textedit = getattr(tab, entry)

        try:
            textedit.setPlainText(str(settings[entry]))
        except KeyError:
            log.warning("{0} criteria missing from settings file.".format(entry))


def save_listviews(tab, settings, listviews):
    """
    Save settings from the QListView selection(s) in the tab.

    Parameters:
    tab         The tab object.
    settings    The dictionary of settings.  This will be mutated.
    listviews   A list of attribute names (str) of QListViews in the tab.
    """

    for entry in listviews:
        listview = getattr(tab, entry)
        datamodel = listview.model()

        selections = []
        for index in listview.selectedIndexes():
            item = datamodel.data(index, Qt.DisplayRole)
            selections.append(item)

        settings[entry] = selections


def load_listviews(tab, settings, listviews):
    """
    Load settings into the QListView selection(s) in the tab.

    Parameters:
    tab         The tab object.
    settings    The dictionary of settings.
    listviews   A list of attribute names (str) of QListViews in the tab.
    """

    log = logging.getLogger(__name__)

    # set list selections
    for entry in listviews:
        try:
            selections = list(settings[entry])
        except KeyError:
            log.warning("{0} criteria missing from settings file.".format(entry))
            continue
        except TypeError:
            msg = "Invalid list for {0} criteria: {1!r}".format(entry, settings[entry])
            log.critical(msg)
            raise TypeError(msg)

        if not selections:
            continue

        listview = getattr(tab, entry)
        selectionmodel = listview.selectionModel()
        selectionmodel.clear()
        datamodel = listview.selectionModel().model()

        for row in range(datamodel.rowCount()):
            index = datamodel.createIndex(row, 0)
            item = datamodel.data(index, Qt.DisplayRole)

            if item in selections:
                selectionmodel.select(index, QItemSelectionModel.Select)


def save_comboboxes(tab, settings, comboboxes):
    """
    Save settings from the QComboBox selection in the tab.

    Parameters:
    tab         The tab object.
    settings    The dictionary of settings.  This will be mutated.
    comboboxes  A list of attribute names (str) of QListViews in the tab.
    """

    for entry in comboboxes:
        combobox = getattr(tab, entry)
        settings[entry] = combobox.currentData(Qt.DisplayRole)


def load_comboboxes(tab, settings, comboboxes):
    """
    Load settings into the QComboBox selection in the tab.

    Parameters:
    tab         The tab object.
    settings    The dictionary of settings.
    comboboxes  A list of attribute names (str) of QListViews in the tab.
    """

    log = logging.getLogger(__name__)

    for entry in comboboxes:
        try:
            selection = str(settings[entry])
        except KeyError:
            log.warning("{0} criteria missing from settings file.".format(entry))
            continue

        combobox = getattr(tab, entry)
        combobox.setCurrentText(selection)


def save_spinboxes(tab, settings, spinboxes):
    """
    Save settings from the QSpinBox value in the tab.

    Parameters:
    tab         The tab object.
    settings    The dictionary of settings.  This will be mutated.
    spinboxes   A list of attribute names (str) of QListViews in the tab.
    """

    for entry in spinboxes:
        spinbox = getattr(tab, entry)
        settings[entry] = spinbox.value()


def load_spinboxes(tab, settings, spinboxes):
    """
    Load settings into the QSpinBox value in the tab.

    Parameters:
    tab         The tab object.
    settings    The dictionary of settings.
    spinboxes   A list of attribute names (str) of QListViews in the tab.
    """

    log = logging.getLogger(__name__)

    for entry in spinboxes:
        try:
            value = int(settings[entry])
        except KeyError:
            log.warning("{0} criteria missing from settings file.".format(entry))
            continue
        except (ValueError, TypeError) as ex:
            msg = "Invalid value for {0} criteria: {1!r}.".format(entry, settings[entry])
            log.critical(msg)
            raise ex.__class__(msg)

        spinbox = getattr(tab, entry)
        spinbox.setValue(value)
