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
from PyQt5.QtWidgets import QDialogButtonBox, QScrollArea

from ..widget import SEToolsWidget


class AnalysisTab(SEToolsWidget, QScrollArea):

    """Base class for Apol analysis tabs."""

    # A QButtonBox which has an Apply button
    # for running the analysis.
    buttonBox = None

    # The set of tab fields that are in error
    errors = None

    # Normal and error palettes to use
    orig_palette = None
    error_palette = None

    #
    # Tab error state
    #
    def set_criteria_error(self, field, error):
        """Set the specified widget to an error state."""
        field.setToolTip("Error: {0}".format(error))
        field.setPalette(self.error_palette)
        self.errors.add(field)
        self._check_query()

    def clear_criteria_error(self, field, tooltip):
        """Clear the specified widget's error state."""
        field.setToolTip(tooltip)
        field.setPalette(self.orig_palette)
        self.errors.discard(field)
        self._check_query()

    def _check_query(self):
        button = self.buttonBox.button(QDialogButtonBox.Apply)
        enabled = not self.errors
        button.setEnabled(enabled)
        button.setToolTip("Run the analysis." if enabled else "There are errors in the tab.")

    #
    # Save/Load tab
    #
    def save(self):
        raise NotImplementedError

    def load(self, settings):
        raise NotImplementedError

    #
    # Results runner
    #
    def run(self, button):
        raise NotImplementedError

    def update_complete(self, count):
        raise NotImplementedError
