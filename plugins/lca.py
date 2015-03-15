import idaapi
from idaapi import *
from idautils import *
from idc import *
import sark
import sark.graph


class GraphCloser(action_handler_t):
    def __init__(self, graph):
        action_handler_t.__init__(self)
        self.graph = graph

    def activate(self, ctx):
        self.graph.Close()

    def update(self, ctx):
        return AST_ENABLE_ALWAYS


class NxGraph(GraphViewer):
    def __init__(self, name, graph, sources, targets):
        self.title = name
        GraphViewer.__init__(self, self.title)
        self._graph = graph
        self._sources = sources
        self._targets = targets
        self._ids = {}

    def OnRefresh(self):
        self.Clear()
        ids = {}
        for frm, to in self._graph.edges_iter():
            if frm not in ids:
                ids[frm] = self.AddNode(frm)
            frm = ids[frm]

            if to not in ids:
                ids[to] = self.AddNode(to)
            to = ids[to]

            self.AddEdge(frm, to)

        self._ids = ids

        return True

    def OnGetText(self, node_id):
        return Name(self[node_id])

    def Show(self):
        if not GraphViewer.Show(self):
            return False
        actname = "graph_closer:%s" % self.title
        register_action(action_desc_t(actname, "Close %s" % self.title, GraphCloser(self)))
        attach_action_to_popup(self.GetTCustomControl(), None, actname)

        ids = self._ids

        for source in self._sources:
            ni = idaapi.node_info_t()
            ni.bg_color = 0xFF00FF
            self.SetNodeInfo(ids[source], ni, idaapi.NIF_BG_COLOR)

        for target in self._targets:
            ni = idaapi.node_info_t()
            ni.bg_color = 0xFFFF00
            self.SetNodeInfo(ids[target], ni, idaapi.NIF_BG_COLOR)


    def OnDblClick(self, node_id):
        Jump(self[node_id])



        return True


def show_graph():
    idb_graph = sark.graph.idb_to_graph()
    targets = [0x004243C8, 0x004243DC, 0x004243E8, 0x004243F0]
    targets = [0x00441580, 0x00441584, 0x0044157C]
    sources = sark.graph.lowest_common_ancestors(idb_graph, targets)
    lca_graph = sark.graph.get_lca_graph(idb_graph, targets, sources)
    ida_g = NxGraph("Test", lca_graph, sources, targets)
    ida_g.Show()
    return ida_g

g = show_graph()

######################################################################
class LCA(idaapi.plugin_t):
    flags = 0
    comment = "Lowest Common Ancestors"
    help = "Lowest Common Ancestors"
    wanted_name = "Lowest Common Ancestors"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return LCA()