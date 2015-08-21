from itertools import repeat
from awesome.context import ignored
import sark
import idaapi
import networkx as nx
from collections import deque
from sark import exceptions

MENU_PATH_GRAPHS = 'View/Graphs/'


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
    call_graph = nx.DiGraph()

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
        for xref in get_xrefs(ea):
            frm = _try_get_function_start(xref.frm)
            to_ = _try_get_function_start(xref.to)

            call_graph.add_edge(frm, to_)

            if to:
                new.add(frm)
            else:
                new.add(to_)

        ea_queue.extend(new)
        distance_queue.extend(repeat(distance_to_go - 1, len(new)))

    return call_graph


def show_callgraph(ea, to=False, distance=4):
    ea = _try_get_function_start(ea)

    call_graph = gen_call_graph(ea, to=to, distance=distance)

    call_graph.node[ea][sark.ui.NXGraph.BG_COLOR] = 0x80

    # Create an NXGraph viewer
    viewer = sark.ui.NXGraph(call_graph, handler=sark.ui.AddressNodeHandler())

    # Show the graph
    viewer.Show()


class ShowCallgraphTo(sark.ui.ActionHandler):
    TEXT = "Show Callgraph To"

    def _activate(self, ctx):
        distance = idaapi.asklong(4, 'Distance To Source')
        show_callgraph(ctx.cur_ea, to=True, distance=distance)


class ShowCallgraphFrom(sark.ui.ActionHandler):
    TEXT = "Show Callgraph From"

    def _activate(self, ctx):
        distance = idaapi.asklong(4, 'Distance From Source')
        show_callgraph(ctx.cur_ea, to=False, distance=distance)


class CallgraphPlugin(idaapi.plugin_t):
    flags = 0
    comment = 'Show Callgraphs'
    help = 'Shows callgraphs.'
    wanted_name = 'Callgraph'
    wanted_hotkey = ""

    def init(self):
        ShowCallgraphTo.register()
        ShowCallgraphFrom.register()
        idaapi.attach_action_to_menu(MENU_PATH_GRAPHS, ShowCallgraphTo.get_name(), 0)
        idaapi.attach_action_to_menu(MENU_PATH_GRAPHS, ShowCallgraphFrom.get_name(), 0)
        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.detach_action_from_menu(MENU_PATH_GRAPHS, ShowCallgraphTo.get_name())
        idaapi.detach_action_from_menu(MENU_PATH_GRAPHS, ShowCallgraphFrom.get_name())
        ShowCallgraphTo.unregister()
        ShowCallgraphFrom.unregister()

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return CallgraphPlugin()
