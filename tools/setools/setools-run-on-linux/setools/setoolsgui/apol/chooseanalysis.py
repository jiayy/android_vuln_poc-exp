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

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QDialog, QTreeWidgetItem

from ..widget import SEToolsWidget

# Analysis tabs:
from .boolquery import BoolQueryTab
from .boundsquery import BoundsQueryTab
from .categoryquery import CategoryQueryTab
from .commonquery import CommonQueryTab
from .constraintquery import ConstraintQueryTab
from .defaultquery import DefaultQueryTab
from .dta import DomainTransitionAnalysisTab
from .fsusequery import FSUseQueryTab
from .genfsconquery import GenfsconQueryTab
from .infoflow import InfoFlowAnalysisTab
from .initsidquery import InitialSIDQueryTab
from .mlsrulequery import MLSRuleQueryTab
from .netifconquery import NetifconQueryTab
from .nodeconquery import NodeconQueryTab
from .objclassquery import ObjClassQueryTab
from .portconquery import PortconQueryTab
from .rbacrulequery import RBACRuleQueryTab
from .rolequery import RoleQueryTab
from .sensitivityquery import SensitivityQueryTab
from .summary import SummaryTab
from .terulequery import TERuleQueryTab
from .typeattrquery import TypeAttributeQueryTab
from .typequery import TypeQueryTab
from .userquery import UserQueryTab


# TODO: is there a better way than hardcoding this while still being safe?
tab_map = {"BoolQueryTab": BoolQueryTab,
           "BoundsQueryTab": BoundsQueryTab,
           "CategoryQueryTab": CategoryQueryTab,
           "CommonQueryTab": CommonQueryTab,
           "ConstraintQueryTab": ConstraintQueryTab,
           "DefaultQueryTab": DefaultQueryTab,
           "DomainTransitionAnalysisTab": DomainTransitionAnalysisTab,
           "FSUseQueryTab": FSUseQueryTab,
           "GenfsconQueryTab": GenfsconQueryTab,
           "InfoFlowAnalysisTab": InfoFlowAnalysisTab,
           "InitialSIDQueryTab": InitialSIDQueryTab,
           "MLSRuleQueryTab": MLSRuleQueryTab,
           "NetifconQueryTab": NetifconQueryTab,
           "NodeconQueryTab": NodeconQueryTab,
           "ObjClassQueryTab": ObjClassQueryTab,
           "PortconQueryTab": PortconQueryTab,
           "RBACRuleQueryTab": RBACRuleQueryTab,
           "RoleQueryTab": RoleQueryTab,
           "SensitivityQueryTab": SensitivityQueryTab,
           "SummaryTab": SummaryTab,
           "TERuleQueryTab": TERuleQueryTab,
           "TypeAttributeQueryTab": TypeAttributeQueryTab,
           "TypeQueryTab": TypeQueryTab,
           "UserQueryTab": UserQueryTab}


class ChooseAnalysis(SEToolsWidget, QDialog):

    """
    Dialog for choosing a new analysis

    The below class attributes are used for populating
    the GUI contents and mapping them to the appropriate
    tab widget class for the analysis.
    """

    def __init__(self, parent):
        super(ChooseAnalysis, self).__init__(parent)
        self.parent = parent
        self.setupUi()

    def setupUi(self):
        self.load_ui("apol/choose_analysis.ui")

    def show(self, mls):
        analysis_map = {"Domain Transition Analysis": DomainTransitionAnalysisTab,
                        "Information Flow Analysis": InfoFlowAnalysisTab}
        components_map = {"Booleans": BoolQueryTab,
                          "Commons": CommonQueryTab,
                          "Roles": RoleQueryTab,
                          "Object Classes": ObjClassQueryTab,
                          "Types": TypeQueryTab,
                          "Type Attributes": TypeAttributeQueryTab,
                          "Users": UserQueryTab}
        rule_map = {"Constraints": ConstraintQueryTab,
                    "RBAC Rules": RBACRuleQueryTab,
                    "TE Rules": TERuleQueryTab}
        labeling_map = {"Fs_use_* Statements": FSUseQueryTab,
                        "Genfscon Statements": GenfsconQueryTab,
                        "Initial SID Statements": InitialSIDQueryTab,
                        "Netifcon Statements": NetifconQueryTab,
                        "Nodecon Statements": NodeconQueryTab,
                        "Portcon Statements": PortconQueryTab}
        general_choices = {"Summary": SummaryTab}
        other_choices = {"Bounds": BoundsQueryTab,
                         "Defaults": DefaultQueryTab}
        analysis_choices = {"Components": components_map,
                            "Rules": rule_map,
                            "Analyses": analysis_map,
                            "Labeling": labeling_map,
                            "General": general_choices,
                            "Other": other_choices}

        if mls:
            rule_map["MLS Rules"] = MLSRuleQueryTab
            components_map["Categories"] = CategoryQueryTab
            components_map["Sensitivities"] = SensitivityQueryTab

        # populate the item list:
        self.analysisTypes.clear()
        for groupname, group in analysis_choices.items():
            groupitem = QTreeWidgetItem(self.analysisTypes)
            groupitem.setText(0, groupname)
            groupitem._tab_class = None
            for entryname, cls in group.items():
                item = QTreeWidgetItem(groupitem)
                item.setText(0, entryname)
                item._tab_class = cls
                groupitem.addChild(item)

        self.analysisTypes.expandAll()
        self.analysisTypes.sortByColumn(0, Qt.AscendingOrder)
        super(ChooseAnalysis, self).show()

    def accept(self, item=None):
        try:
            if not item:
                # .ui is set for single item selection.
                item = self.analysisTypes.selectedItems()[0]

            title = item.text(0)
            self.parent.create_new_analysis(title, item._tab_class)
        except (IndexError, TypeError):
            # IndexError: nothing is selected
            # TypeError: one of the group items was selected.
            pass
        else:
            super(ChooseAnalysis, self).accept()
