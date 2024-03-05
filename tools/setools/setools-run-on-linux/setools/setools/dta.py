# Copyright 2014-2015, Tresys Technology, LLC
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
# pylint: disable=unsubscriptable-object

import itertools
import logging
from collections import defaultdict, namedtuple
from contextlib import suppress

import networkx as nx
from networkx.exception import NetworkXError, NetworkXNoPath, NodeNotFound

from .descriptors import EdgeAttrDict, EdgeAttrList
from .policyrep import TERuletype

__all__ = ['DomainTransitionAnalysis']

# Return values for the analysis
# are in the following tuple formats:
step_output = namedtuple("step", ["source",
                                  "target",
                                  "transition",
                                  "entrypoints",
                                  "setexec",
                                  "dyntransition",
                                  "setcurrent"])

entrypoint_output = namedtuple("entrypoints", ["name",
                                               "entrypoint",
                                               "execute",
                                               "type_transition"])


class DomainTransitionAnalysis:

    """Domain transition analysis."""

    def __init__(self, policy, reverse=False, exclude=None):
        """
        Parameter:
        policy   The policy to analyze.
        """
        self.log = logging.getLogger(__name__)

        self.policy = policy
        self.exclude = exclude
        self.reverse = reverse
        self.rebuildgraph = True
        self.rebuildsubgraph = True
        self.G = nx.DiGraph()
        self.subG = None

    @property
    def reverse(self):
        return self._reverse

    @reverse.setter
    def reverse(self, direction):
        self._reverse = bool(direction)
        self.rebuildsubgraph = True

    @property
    def exclude(self):
        return self._exclude

    @exclude.setter
    def exclude(self, types):
        if types:
            self._exclude = [self.policy.lookup_type(t) for t in types]
        else:
            self._exclude = []

        self.rebuildsubgraph = True

    def shortest_path(self, source, target):
        """
        Generator which yields one shortest domain transition path
        between the source and target types (there may be more).

        Parameters:
        source  The source type.
        target  The target type.

        Yield: generator(steps)

        steps   A generator that returns the tuple of
                source, target, and rules for each
                domain transition.
        """
        s = self.policy.lookup_type(source)
        t = self.policy.lookup_type(target)

        if self.rebuildsubgraph:
            self._build_subgraph()

        self.log.info("Generating one domain transition path from {0} to {1}...".format(s, t))

        with suppress(NetworkXNoPath, NodeNotFound):
            # NodeNotFound: the type is valid but not in graph, e.g. excluded
            # NetworkXNoPath: no paths or the target type is
            # not in the graph
            yield self.__generate_steps(nx.shortest_path(self.subG, s, t))

    def all_paths(self, source, target, maxlen=2):
        """
        Generator which yields all domain transition paths between
        the source and target up to the specified maximum path
        length.

        Parameters:
        source   The source type.
        target   The target type.
        maxlen   Maximum length of paths.

        Yield: generator(steps)

        steps    A generator that returns the tuple of
                 source, target, and rules for each
                 domain transition.
        """
        if maxlen < 1:
            raise ValueError("Maximum path length must be positive.")

        s = self.policy.lookup_type(source)
        t = self.policy.lookup_type(target)

        if self.rebuildsubgraph:
            self._build_subgraph()

        self.log.info("Generating all domain transition paths from {0} to {1}, max length {2}...".
                      format(s, t, maxlen))

        with suppress(NetworkXNoPath, NodeNotFound):
            # NodeNotFound: the type is valid but not in graph, e.g. excluded
            # NetworkXNoPath: no paths or the target type is
            # not in the graph
            for path in nx.all_simple_paths(self.subG, s, t, maxlen):
                yield self.__generate_steps(path)

    def all_shortest_paths(self, source, target):
        """
        Generator which yields all shortest domain transition paths
        between the source and target types.

        Parameters:
        source   The source type.
        target   The target type.

        Yield: generator(steps)

        steps    A generator that returns the tuple of
                 source, target, and rules for each
                 domain transition.
        """
        s = self.policy.lookup_type(source)
        t = self.policy.lookup_type(target)

        if self.rebuildsubgraph:
            self._build_subgraph()

        self.log.info("Generating all shortest domain transition paths from {0} to {1}...".
                      format(s, t))

        with suppress(NetworkXNoPath, NodeNotFound):
            # NodeNotFound: the type is valid but not in graph, e.g. excluded
            # NetworkXNoPath: no paths or the target type is
            # not in the graph
            for path in nx.all_shortest_paths(self.subG, s, t):
                yield self.__generate_steps(path)

    def transitions(self, type_):
        """
        Generator which yields all domain transitions out of a
        specified source type.

        Parameters:
        type_   The starting type.

        Yield: generator(steps)

        steps   A generator that returns the tuple of
                source, target, and rules for each
                domain transition.
        """
        s = self.policy.lookup_type(type_)

        if self.rebuildsubgraph:
            self._build_subgraph()

        self.log.info("Generating all domain transitions {1} {0}".
                      format(s, "in to" if self.reverse else "out from"))

        with suppress(NetworkXError):
            # NetworkXError: the type is valid but not in graph, e.g. excluded
            for source, target in self.subG.out_edges(s):
                edge = Edge(self.subG, source, target)

                if self.reverse:
                    real_source, real_target = target, source
                else:
                    real_source, real_target = source, target

                yield step_output(real_source, real_target,
                                  edge.transition,
                                  self.__generate_entrypoints(edge),
                                  edge.setexec,
                                  edge.dyntransition,
                                  edge.setcurrent)

    def get_stats(self):  # pragma: no cover
        """
        Get the domain transition graph statistics.

        Return: str
        """
        if self.rebuildgraph:
            self._build_graph()

        return nx.info(self.G)

    #
    # Internal functions follow
    #
    @staticmethod
    def __generate_entrypoints(edge):
        """
        Creates a list of entrypoint, execute, and
        type_transition rules for each entrypoint.

        Parameter:
        data     The dictionary of entrypoints.

        Return: list of tuple(type, entry, exec, trans)

        type     The entrypoint type.
        entry    The list of entrypoint rules.
        exec     The list of execute rules.
        trans    The list of type_transition rules.
        """
        return [entrypoint_output(e, edge.entrypoint[e], edge.execute[e], edge.type_transition[e])
                for e in edge.entrypoint]

    def __generate_steps(self, path):
        """
        Generator which yields the source, target, and associated rules
        for each domain transition.

        Parameter:
        path     A list of graph node names representing an information flow path.

        Yield: tuple(source, target, transition, entrypoints,
                     setexec, dyntransition, setcurrent)

        source          The source type for this step of the domain transition.
        target          The target type for this step of the domain transition.
        transition      The list of transition rules.
        entrypoints     Generator which yields entrypoint-related rules.
        setexec         The list of setexec rules.
        dyntranstion    The list of dynamic transition rules.
        setcurrent      The list of setcurrent rules.
        """

        for s in range(1, len(path)):
            source = path[s - 1]
            target = path[s]
            edge = Edge(self.subG, source, target)

            # Yield the actual source and target.
            # The above perspective is reversed
            # if the graph has been reversed.
            if self.reverse:
                real_source, real_target = target, source
            else:
                real_source, real_target = source, target

            yield step_output(real_source, real_target,
                              edge.transition,
                              self.__generate_entrypoints(edge),
                              edge.setexec,
                              edge.dyntransition,
                              edge.setcurrent)

    #
    # Graph building functions
    #

    # Domain transition requirements:
    #
    # Standard transitions a->b:
    # allow a b:process transition;
    # allow a b_exec:file execute;
    # allow b b_exec:file entrypoint;
    #
    # and at least one of:
    # allow a self:process setexec;
    # type_transition a b_exec:process b;
    #
    # Dynamic transition x->y:
    # allow x y:process dyntransition;
    # allow x self:process setcurrent;
    #
    # Algorithm summary:
    # 1. iterate over all rules
    #   1. skip non allow/type_transition rules
    #   2. if process transition or dyntransition, create edge,
    #      initialize rule lists, add the (dyn)transition rule
    #   3. if process setexec or setcurrent, add to appropriate dict
    #      keyed on the subject
    #   4. if file exec, entrypoint, or type_transition:process,
    #      add to appropriate dict keyed on subject,object.
    # 2. Iterate over all graph edges:
    #   1. if there is a transition rule (else add to invalid
    #      transition list):
    #       1. use set intersection to find matching exec
    #          and entrypoint rules. If none, add to invalid
    #          transition list.
    #       2. for each valid entrypoint, add rules to the
    #          edge's lists if there is either a
    #          type_transition for it or the source process
    #          has setexec permissions.
    #       3. If there are neither type_transitions nor
    #          setexec permissions, add to the invalid
    #          transition list
    #   2. if there is a dyntransition rule (else add to invalid
    #      dyntrans list):
    #       1. If the source has a setcurrent rule, add it
    #          to the edge's list, else add to invalid
    #          dyntransition list.
    # 3. Iterate over all graph edges:
    #   1. if the edge has an invalid trans and dyntrans, delete
    #      the edge.
    #   2. if the edge has an invalid trans, clear the related
    #      lists on the edge.
    #   3. if the edge has an invalid dyntrans, clear the related
    #      lists on the edge.
    #
    def _build_graph(self):
        self.G.clear()
        self.G.name = "Domain transition graph for {0}.".format(self.policy)

        self.log.info("Building domain transition graph from {0}...".format(self.policy))

        # hash tables keyed on domain type
        setexec = defaultdict(list)
        setcurrent = defaultdict(list)

        # hash tables keyed on (domain, entrypoint file type)
        # the parameter for defaultdict has to be callable
        # hence the lambda for the nested defaultdict
        execute = defaultdict(lambda: defaultdict(list))
        entrypoint = defaultdict(lambda: defaultdict(list))

        # hash table keyed on (domain, entrypoint, target domain)
        type_trans = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

        for rule in self.policy.terules():
            if rule.ruletype == TERuletype.allow:
                if rule.tclass not in ["process", "file"]:
                    continue

                perms = rule.perms

                if rule.tclass == "process":
                    if "transition" in perms:
                        for s, t in itertools.product(rule.source.expand(), rule.target.expand()):
                            # only add edges if they actually
                            # transition to a new type
                            if s != t:
                                edge = Edge(self.G, s, t, create=True)
                                edge.transition.append(rule)

                    if "dyntransition" in perms:
                        for s, t in itertools.product(rule.source.expand(), rule.target.expand()):
                            # only add edges if they actually
                            # transition to a new type
                            if s != t:
                                e = Edge(self.G, s, t, create=True)
                                e.dyntransition.append(rule)

                    if "setexec" in perms:
                        for s in rule.source.expand():
                            setexec[s].append(rule)

                    if "setcurrent" in perms:
                        for s in rule.source.expand():
                            setcurrent[s].append(rule)

                else:
                    if "execute" in perms:
                        for s, t in itertools.product(
                                rule.source.expand(),
                                rule.target.expand()):
                            execute[s][t].append(rule)

                    if "entrypoint" in perms:
                        for s, t in itertools.product(rule.source.expand(), rule.target.expand()):
                            entrypoint[s][t].append(rule)

            elif rule.ruletype == TERuletype.type_transition:
                if rule.tclass != "process":
                    continue

                d = rule.default
                for s, t in itertools.product(rule.source.expand(), rule.target.expand()):
                    type_trans[s][t][d].append(rule)

        invalid_edge = []
        clear_transition = []
        clear_dyntransition = []

        for s, t in self.G.edges():
            edge = Edge(self.G, s, t)
            invalid_trans = False
            invalid_dyntrans = False

            if edge.transition:
                # get matching domain exec w/entrypoint type
                entry = set(entrypoint[t].keys())
                exe = set(execute[s].keys())
                match = entry.intersection(exe)

                if not match:
                    # there are no valid entrypoints
                    invalid_trans = True
                else:
                    # TODO try to improve the
                    # efficiency in this loop
                    for m in match:
                        # pylint: disable=unsupported-assignment-operation
                        if s in setexec or type_trans[s][m]:
                            # add key for each entrypoint
                            edge.entrypoint[m] += entrypoint[t][m]
                            edge.execute[m] += execute[s][m]

                        if type_trans[s][m][t]:
                            edge.type_transition[m] += type_trans[s][m][t]

                    if s in setexec:
                        edge.setexec.extend(setexec[s])

                    if not edge.setexec and not edge.type_transition:
                        invalid_trans = True
            else:
                invalid_trans = True

            if edge.dyntransition:
                if s in setcurrent:
                    edge.setcurrent.extend(setcurrent[s])
                else:
                    invalid_dyntrans = True
            else:
                invalid_dyntrans = True

            # cannot change the edges while iterating over them,
            # so keep appropriate lists
            if invalid_trans and invalid_dyntrans:
                invalid_edge.append(edge)
            elif invalid_trans:
                clear_transition.append(edge)
            elif invalid_dyntrans:
                clear_dyntransition.append(edge)

        # Remove invalid transitions
        self.G.remove_edges_from(invalid_edge)
        for edge in clear_transition:
            # if only the regular transition is invalid,
            # clear the relevant lists
            del edge.transition
            del edge.execute
            del edge.entrypoint
            del edge.type_transition
            del edge.setexec
        for edge in clear_dyntransition:
            # if only the dynamic transition is invalid,
            # clear the relevant lists
            del edge.dyntransition
            del edge.setcurrent

        self.rebuildgraph = False
        self.rebuildsubgraph = True
        self.log.info("Completed building domain transition graph.")
        self.log.debug("Graph stats: nodes: {0}, edges: {1}.".format(
            nx.number_of_nodes(self.G),
            nx.number_of_edges(self.G)))

    def __remove_excluded_entrypoints(self):
        invalid_edges = []
        for source, target in self.subG.edges():
            edge = Edge(self.subG, source, target)
            entrypoints = set(edge.entrypoint)
            entrypoints.intersection_update(self.exclude)

            if not entrypoints:
                # short circuit if there are no
                # excluded entrypoint types on
                # this edge.
                continue

            for e in entrypoints:
                # clear the entrypoint data
                # pylint: disable=unsupported-delete-operation
                del edge.entrypoint[e]
                del edge.execute[e]

                with suppress(KeyError):  # setexec
                    del edge.type_transition[e]

            # cannot delete the edges while iterating over them
            if not edge.entrypoint and not edge.dyntransition:
                invalid_edges.append(edge)

        self.subG.remove_edges_from(invalid_edges)

    def _build_subgraph(self):
        if self.rebuildgraph:
            self._build_graph()

        self.log.info("Building domain transition subgraph.")
        self.log.debug("Excluding {0}".format(self.exclude))
        self.log.debug("Reverse {0}".format(self.reverse))

        # reverse graph for reverse DTA
        if self.reverse:
            self.subG = self.G.reverse(copy=True)
        else:
            self.subG = self.G.copy()

        if self.exclude:
            # delete excluded domains from subgraph
            self.subG.remove_nodes_from(self.exclude)

            # delete excluded entrypoints from subgraph
            self.__remove_excluded_entrypoints()

        self.rebuildsubgraph = False
        self.log.info("Completed building domain transition subgraph.")
        self.log.debug("Subgraph stats: nodes: {0}, edges: {1}.".format(
            nx.number_of_nodes(self.subG),
            nx.number_of_edges(self.subG)))


class Edge:

    """
    A graph edge.  Also used for returning domain transition steps.

    Parameters:
    graph       The NetworkX graph.
    source      The source type of the edge.
    target      The target tyep of the edge.

    Keyword Parameters:
    create      (T/F) create the edge if it does not exist.
                The default is False.
    """

    transition = EdgeAttrList('transition')
    setexec = EdgeAttrList('setexec')
    dyntransition = EdgeAttrList('dyntransition')
    setcurrent = EdgeAttrList('setcurrent')
    entrypoint = EdgeAttrDict('entrypoint')
    execute = EdgeAttrDict('execute')
    type_transition = EdgeAttrDict('type_transition')

    def __init__(self, graph, source, target, create=False):
        self.G = graph
        self.source = source
        self.target = target

        if not self.G.has_edge(source, target):
            if not create:
                raise ValueError("Edge does not exist in graph")
            else:
                self.G.add_edge(source, target)
                self.transition = None
                self.entrypoint = None
                self.execute = None
                self.type_transition = None
                self.setexec = None
                self.dyntransition = None
                self.setcurrent = None

    def __getitem__(self, key):
        # This is implemented so this object can be used in NetworkX
        # functions that operate on (source, target) tuples
        if isinstance(key, slice):
            return [self._index_to_item(i) for i in range(* key.indices(2))]
        else:
            return self._index_to_item(key)

    def _index_to_item(self, index):
        """Return source or target based on index."""
        if index == 0:
            return self.source
        elif index == 1:
            return self.target
        else:
            raise IndexError("Invalid index (edges only have 2 items): {0}".format(index))
