import collections
import itertools
import networkx as nx
from .code.function import functions, Function
from contextlib import suppress
from . import exceptions


def lowest_common_ancestors(G, targets):
    common_ancestors = None
    all_ancestors = set()
    for target in targets:
        parents = set()
        q = collections.deque()
        q.append(target)

        while q:
            n = q.popleft()
            if n in parents:
                continue
            for p in G.predecessors(n):
                q.append(p)
            parents.add(n)

        all_ancestors.update(parents)

        if common_ancestors is None:
            common_ancestors = parents
        else:
            common_ancestors &= parents

    lowest_common = set()
    if common_ancestors is not None:
        for p in common_ancestors:
            if any(child not in common_ancestors and child in all_ancestors for child in G.successors(p)):
                lowest_common.add(p)

    return lowest_common


def _try_get_function_start(ea):
    with suppress(exceptions.SarkNoFunction):
        return Function(ea).start_ea

    return ea


def get_idb_graph():
    """Export IDB to a NetworkX graph.

    Use xrefs to and from functions to build a DiGraph containing all
    the functions in the IDB and all the links between them.
    The graph can later be used to perform analysis on the IDB.

    :return: nx.DiGraph()
    """
    digraph = nx.DiGraph()

    for function in functions():
        for xref in itertools.chain(function.xrefs_from, function.xrefs_to):
            frm = _try_get_function_start(xref.frm)
            to = _try_get_function_start(xref.to)

            digraph.add_edge(frm, to)

    return digraph


def get_lca_graph(G, targets, lca_sources=None):
    if lca_sources is None:
        lca_sources = lowest_common_ancestors(G, targets)

    lca_graph = nx.DiGraph()

    for source in lca_sources:
        for target in targets:
            path = nx.shortest_path(G, source, target)

            for frm, to in zip(path[:-1], path[1:]):
                lca_graph.add_edge(frm, to)

    return lca_graph