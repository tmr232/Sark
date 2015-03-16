import idaapi
from idaapi import *
from idautils import *
from idc import *
import sark
import sark.graph
import networkx as nx
import sark.ui
import idc


class GraphCloser(action_handler_t):
    def __init__(self, graph):
        action_handler_t.__init__(self)
        self.graph = graph

    def activate(self, ctx):
        self.graph.Close()

    def update(self, ctx):
        return AST_ENABLE_ALWAYS


class GraphTest(action_handler_t):
    def __init__(self, graph):
        action_handler_t.__init__(self)
        self.graph = graph

    def activate(self, ctx):
        idaapi.msg("\nNode ID: {}".format(self.graph._current_node_id))

    def update(self, ctx):
        return AST_ENABLE_ALWAYS


class LCAGraph(GraphViewer):
    def __init__(self, title):
        self._title = title
        GraphViewer.__init__(self, self._title)

        self._targets = set()
        self._sources = None

        # This might take a while...
        self._idb_graph = sark.graph.idb_to_graph()

        self._lca_graph = None

        self.hooks = None

    def OnGetText(self, node_id):
        return idc.Name(self[node_id])

    def Show(self):
        if not GraphViewer.Show(self):
            return False

        return True

    def add_target(self, target):
        self._targets.add(target)

    def add_targets(self, targets):
        for target in targets:
            self.add_target(target)

    def OnRefresh(self):
        self.Clear()

        if self._targets and self._lca_graph is None:
            # This might take a while...
            self._lca_graph = sark.graph.get_lca_graph(self._idb_graph, self._targets, self._sources)

        node_ids = {node: self.AddNode(node) for node in self._lca_graph.nodes_iter()}

        for frm, to in self._lca_graph.edges_iter():
            self.AddEdge(node_ids[frm], node_ids[to])

        return True

    def OnActivate(self):
        # Refresh on every activation to make sure the names are up to date.
        self.Refresh()

        return True

    def OnDeactivate(self):
        # This is an ugly hack. There probably are better ways.
        if self.hooks:
            self.hooks.unhook()

    def OnDblClick(self, node_id):
        # On double-click, jump to the clicked address.
        idaapi.jumpto(self[node_id])

        return True

    def OnClick(self, node_id):
        class Hooks(idaapi.UI_Hooks):
            def __init__(self, viewer):
                super(Hooks, self).__init__()
                self._viewer = viewer

            def finish_populating_tform_popup(self, form, popup):
                if form != self._viewer.GetTForm():
                    idaapi.msg("\nForm Mismatch: {!r} {!r} {!r}".format(form, self._viewer.GetTForm(),
                                                                        self._viewer.GetTCustomControl()))
                class ClickHandler(sark.ui.ActionHandler):
                    TEXT = "On Click!"

                    def _activate(self, ctx):
                        idaapi.msg("\nHello, World!")

                idaapi.attach_dynamic_action_to_popup(form, popup, ClickHandler.get_desc(), None)

        self.hooks = Hooks(self)
        self.hooks.hook()


class NxGraph(GraphViewer):
    def __init__(self, name, graph, sources, targets):
        self.title = name
        GraphViewer.__init__(self, self.title)
        self._graph = graph
        self._sources = sources
        self._targets = targets
        self._ids = {}
        self._rids = {}
        self._current_node_id = 0

    def OnRefresh(self):
        self.Clear()
        ids = {}
        rids = {}
        for frm, to in self._graph.edges_iter():
            if frm not in ids:
                ids[frm] = self.AddNode(frm)
                rids[ids[frm]] = frm
            frm = ids[frm]

            if to not in ids:
                ids[to] = self.AddNode(to)
                rids[ids[to]] = to
            to = ids[to]

            self.AddEdge(frm, to)

        self._ids = ids
        self._rids = rids

        self.paint_nodes()
        return True

    def OnGetText(self, node_id):
        return Name(self[node_id])

    def Show(self):
        if not GraphViewer.Show(self):
            return False
        actname = "graph_closer:%s" % self.title
        register_action(action_desc_t(actname, "Close %s" % self.title, GraphCloser(self)))
        register_action(action_desc_t("Bla1", "Do Something", GraphTest(self)))
        attach_action_to_popup(self.GetTCustomControl(), None, actname)
        attach_action_to_popup(self.GetTCustomControl(), None, "Bla1")

        self.paint_nodes()

        return True


    def OnClick(self, node_id):
        self.paint_nodes()
        self._current_node_id = node_id

        # TODO: Use a different color for every target path.
        if self._rids[node_id] in self._sources:
            for node in nx.descendants(self._graph, self._rids[node_id]):
                if node not in self._sources and node not in self._targets:
                    self.set_node_color(self._ids[node], 0x006666)

        if self._rids[node_id] in self._targets:
            for node in nx.ancestors(self._graph, self._rids[node_id]):
                if node not in self._sources and node not in self._targets:
                    self.set_node_color(self._ids[node], 0x006666)


    def OnDblClick(self, node_id):
        Jump(self[node_id])

    def OnSelect(self, node_id):
        idaapi.msg("\nNode ID: {}".format(node_id))

        return True

    def set_node_color(self, node_id, color):
        ni = idaapi.node_info_t()
        ni.bg_color = color
        self.SetNodeInfo(node_id, ni, idaapi.NIF_BG_COLOR)

    def clear_nodes(self):
        for nid in xrange(self.Count()):
            self.set_node_color(nid, 0xFFFFFFFF)

    def paint_nodes(self):
        self.clear_nodes()
        ids = self._ids
        for source in self._sources:
            node_id = ids[source]
            color = 0x660066
            self.set_node_color(node_id, color)
        for target in self._targets:
            node_id = ids[target]
            color = 0x666600
            self.set_node_color(node_id, color)

    def OnActivate(self):
        self.Refresh()

        self.paint_nodes()
        return True


def show_graph():
    idb_graph = sark.graph.idb_to_graph()
    targets = [0x004243C8, 0x004243DC, 0x004243E8, 0x004243F0]
    # targets = [0x00441580, 0x00441584, 0x0044157C]
    sources = sark.graph.lowest_common_ancestors(idb_graph, targets)
    lca_graph = sark.graph.get_lca_graph(idb_graph, targets, sources)
    ida_g = NxGraph("Test", lca_graph, sources, targets)
    ida_g.Show()
    return ida_g


# g = show_graph()

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
        lca_viewer = LCAGraph("My LCA Graph")
        map(lca_viewer.add_target, [0x004243C8, 0x004243DC, 0x004243E8, 0x004243F0])
        lca_viewer.Show()


def PLUGIN_ENTRY():
    return LCA()