from itertools import repeat
from awesome.context import ignored
import sark
import idaapi
import networkx as nx
from collections import deque
from sark import exceptions
import idc

MENU_PATH_GRAPHS = 'View/Graphs/'


def _try_get_function_start(ea):
    with ignored(exceptions.SarkNoFunction):
        return sark.Function(ea).startEA

    return ea


def _get_best_name(ea):
    try:
        return sark.Function(ea).demangled
    except exceptions.SarkNoFunction:
        name = idc.GetTrueName(ea)
        if name:
            return name
        return '0x{:X}'.format(ea)


def _xrefs_to(function_ea):
    try:
        return sark.Function(function_ea).xrefs_to

    except exceptions.SarkNoFunction:
        return sark.Line(function_ea).xrefs_to


def _xrefs_from(function_ea):
    try:
        return sark.Function(function_ea).xrefs_from

    except exceptions.SarkNoFunction:
        return sark.Line(function_ea).xrefs_from


def gen_xref_graph(ea, to=False, distance=4):
    xref_graph = nx.DiGraph()

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

            xref_graph.add_edge(frm, to_)

            if to:
                new.add(frm)
            else:
                new.add(to_)

        ea_queue.extend(new)
        distance_queue.extend(repeat(distance_to_go - 1, len(new)))

    return xref_graph


def show_xref_graph(ea, to=False, distance=4):
    ea = _try_get_function_start(ea)

    call_graph = gen_xref_graph(ea, to=to, distance=distance)

    call_graph.node[ea][sark.ui.NXGraph.BG_COLOR] = 0x80

    title = 'Xrefs {tofrom} {target} '.format(tofrom='to' if to else 'from',
                                              target=_get_best_name(ea))

    # Create an NXGraph viewer
    viewer = sark.ui.NXGraph(call_graph, handler=sark.ui.AddressNodeHandler(), title=title)

    # Show the graph
    viewer.Show()


if idaapi.IDA_SDK_VERSION < 670:  # This means no `idaapi.action_handler_t`. See http://www.hexblog.com/?p=886
    def show_xrefs_from(*args):
        distance = idaapi.asklong(4, 'Distance From Source')
        show_xref_graph(idc.here(), to=False, distance=distance)


    def show_xrefs_to(*args):
        distance = idaapi.asklong(4, 'Distance To Source')
        show_xref_graph(idc.here(), to=True, distance=distance)


    class XrefsGraphPlugins(idaapi.plugin_t):
        flags = 0
        comment = 'Show xref graphs'
        help = 'Shows xref graphs.'
        wanted_name = 'Xref Graphs'
        wanted_hotkey = ""

        def init(self):
            self.xref_to = idaapi.add_menu_item(MENU_PATH_GRAPHS, 'Xrefs to source', '', 0, show_xrefs_to, None)
            self.xref_from = idaapi.add_menu_item(MENU_PATH_GRAPHS, 'Xrefs from source', '', 0, show_xrefs_from, None)

            return idaapi.PLUGIN_KEEP

        def term(self):
            idaapi.del_menu_item(self.xref_to)
            idaapi.del_menu_item(self.xref_from)

        def run(self, arg):
            pass

else:  # IDA 6.7 and higher
    class ShowXrefsGraphTo(sark.ui.ActionHandler):
        TEXT = "Show xref graph to..."

        def _activate(self, ctx):
            distance = idaapi.asklong(4, 'Distance To Source')
            show_xref_graph(ctx.cur_ea, to=True, distance=distance)


    class ShowXrefsGraphFrom(sark.ui.ActionHandler):
        TEXT = "Show xref graph from..."

        def _activate(self, ctx):
            distance = idaapi.asklong(4, 'Distance From Source')
            show_xref_graph(ctx.cur_ea, to=False, distance=distance)


    class Hooks(idaapi.UI_Hooks):
        def finish_populating_tform_popup(self, form, popup):
            # Or here, after the popup is done being populated by its owner.

            if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
                idaapi.attach_action_to_popup(form, popup, ShowXrefsGraphFrom.get_name(), '')
                idaapi.attach_action_to_popup(form, popup, ShowXrefsGraphTo.get_name(), '')


    class XrefsGraphPlugins(idaapi.plugin_t):
        flags = 0
        comment = 'Show xref graphs'
        help = 'Shows xref graphs.'
        wanted_name = 'Xref Graphs'
        wanted_hotkey = ""

        def init(self):
            ShowXrefsGraphTo.register()
            ShowXrefsGraphFrom.register()
            idaapi.attach_action_to_menu(MENU_PATH_GRAPHS, ShowXrefsGraphTo.get_name(), 0)
            idaapi.attach_action_to_menu(MENU_PATH_GRAPHS, ShowXrefsGraphFrom.get_name(), 0)

            self.hooks = Hooks()
            self.hooks.hook()

            return idaapi.PLUGIN_KEEP

        def term(self):
            self.hooks.unhook()
            idaapi.detach_action_from_menu(MENU_PATH_GRAPHS, ShowXrefsGraphTo.get_name())
            idaapi.detach_action_from_menu(MENU_PATH_GRAPHS, ShowXrefsGraphFrom.get_name())
            ShowXrefsGraphTo.unregister()
            ShowXrefsGraphFrom.unregister()

        def run(self, arg):
            pass


def PLUGIN_ENTRY():
    return XrefsGraphPlugins()
