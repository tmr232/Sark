from itertools import repeat
from awesome.context import ignored
import sark
import idaapi
import networkx as nx
from collections import deque
from sark import exceptions


def _try_get_function_start(ea):
    with ignored(exceptions.SarkNoFunction):
        return sark.Function(ea).startEA

    return ea


def _empty_iterator():
    return
    yield


def _xrefs_to(function_ea):
    try:
        return sark.Function(function_ea).xrefs_to

    except exceptions.SarkNoFunction:
        return _empty_iterator()


def _xrefs_from(function_ea):
    try:
        return sark.Function(function_ea).xrefs_from

    except exceptions.SarkNoFunction:
        return _empty_iterator()


def gen_call_graph(ea, to=False, distance=4):
    graph = nx.DiGraph()

    ea_queue = deque()
    distance_queue = deque()

    ea_queue.append(ea)
    distance_queue.append(distance)

    if to:
        get_xrefs = _xrefs_to
    else:
        get_xrefs = _xrefs_from

    while ea_queue:
        ea = ea_queue.pop()
        distance_to_go = distance_queue.pop()

        if distance_to_go == 0:
            # Distance is exhausted for this path.
            continue

        new = set()
        idaapi.msg('{}\n'.format(ea))
        for xref in get_xrefs(ea):
            frm = _try_get_function_start(xref.frm)
            to_ = _try_get_function_start(xref.to)

            graph.add_edge(frm, to_)

            if to:
                new.add(frm)
            else:
                new.add(to_)

        ea_queue.extend(new)
        distance_queue.extend(repeat(distance_to_go - 1, len(new)))

    # return graph

    # Create an NXGraph viewer
    viewer = sark.ui.NXGraph(graph, handler=sark.ui.AddressNodeHandler())

    # Show the graph
    viewer.Show()
