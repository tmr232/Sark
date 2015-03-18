import idaapi
from idaapi import *
from idautils import *
from idc import *
import sark
import sark.graph
import networkx as nx
import sark.ui
import idc


class ClickHandler(sark.ui.ActionHandler):
    TEXT = "On Click!"

    def _activate(self, ctx):
        idaapi.msg("\nHello, World!")


def remove_target_handler(lca_viewer):
    class RemoveTargetHandler(sark.ui.ActionHandler):
        TEXT = "Remove Target"

        def _activate(self, ctx):
            node_id = lca_viewer.current_node_id
            idaapi.msg("\nLCA: Removing Target: {}".format(idc.Name(lca_viewer[node_id])))
            lca_viewer.remove_target(lca_viewer[node_id])
            lca_viewer.rebuild_graph()
            lca_viewer.Refresh()


    return RemoveTargetHandler


def disable_source_handler(lca_viewer):
    class DisableSourceHandler(sark.ui.ActionHandler):
        TEXT = "Disable Source"

        def _activate(self, ctx):
            node_id = lca_viewer.current_node_id
            lca_viewer.disable_source(lca_viewer[node_id])
            lca_viewer.rebuild_graph()
            lca_viewer.Refresh()


    return DisableSourceHandler


def enable_source_handler(lca_viewer):
    class EnableSourceHandler(sark.ui.ActionHandler):
        TEXT = "Enable Source"

        def _activate(self, ctx):
            node_id = lca_viewer.current_node_id
            lca_viewer.enable_source(lca_viewer[node_id])
            lca_viewer.rebuild_graph()
            lca_viewer.Refresh()


    return EnableSourceHandler


def add_address_handler(lca_viewer):
    class AddAddressHandler(sark.ui.ActionHandler):
        TEXT = "Add Target Function"
        HOTKEY = "Shift+Space"

        def _activate(self, ctx):
            ea = idaapi.asklong(0, "Add LCA Target")
            if ea is None:
                return

            lca_viewer.add_target(ea)
            lca_viewer.rebuild_graph()
            lca_viewer.Refresh()


    return AddAddressHandler


def add_function_handler(lca_viewer):
    class AddFunctionHandler(sark.ui.ActionHandler):
        TEXT = "Add Target Function"
        HOTKEY = "Space"

        def _activate(self, ctx):
            func = idaapi.choose_func("Add LCA Target", 0)
            if not func:
                return

            idaapi.msg("Got func at {}".format(func.startEA))

            lca_viewer.add_target(func.startEA)
            lca_viewer.rebuild_graph()
            lca_viewer.Refresh()
            lca_viewer.Show()

    return AddFunctionHandler


class LCAGraph(GraphViewer):
    def __init__(self, title):
        self._title = title
        GraphViewer.__init__(self, self._title)

        self._targets = set()
        self._sources = set()

        # This might take a while...
        self._idb_graph = sark.graph.idb_to_graph()

        self._lca_graph = None

        self._handlers = [add_function_handler(self),
                          add_address_handler(self)]

        self._current_node_id = 0

        self._disabled_sources = set()

        self._remove_target_handler = remove_target_handler(self)
        self._enable_source_handler = enable_source_handler(self)
        self._disable_source_handler = disable_source_handler(self)


    @property
    def current_node_id(self):
        return self._current_node_id

    def OnGetText(self, node_id):
        return idc.Name(self[node_id])

    def _register_handlers(self):
        for handler in self._handlers:
            handler.register()

    def Show(self):
        if not GraphViewer.Show(self):
            return False

        self._register_handlers()

        return True

    def disable_source(self, source):
        self._disabled_sources.add(source)

    def enable_source(self, source):
        self._disabled_sources.remove(source)

    def add_target(self, target):
        self._targets.add(target)

    def remove_target(self, target):
        self._targets.remove(target)

    def add_targets(self, targets):
        for target in targets:
            self.add_target(target)

    def rebuild_graph(self):
        self._sources = sark.graph.lowest_common_ancestors(self._idb_graph, self._targets)

        # Remove disabled sources from the connected graph.
        active_sources = self._sources - self._disabled_sources
        if active_sources:
            self._lca_graph = sark.graph.get_lca_graph(self._idb_graph, self._targets, active_sources)
        else:
            self._lca_graph = nx.DiGraph()
            self._lca_graph.add_nodes_from(self._targets)

        # Make sure the disabled sources are still shown.
        self._lca_graph.add_nodes_from(self._disabled_sources)


    def OnRefresh(self):
        self.Clear()

        if self._targets and self._lca_graph is None:
            # This might take a while...
            self.rebuild_graph()

        node_ids = {node: self.AddNode(node) for node in self._lca_graph.nodes_iter()}

        for frm, to in self._lca_graph.edges_iter():
            self.AddEdge(node_ids[frm], node_ids[to])

        return True

    def OnActivate(self):
        # Refresh on every activation to make sure the names are up to date.
        self.Refresh()
        self._register_handlers()
        return True

    def _unregister_handlers(self):
        for handler in self._handlers:
            handler.unregister()

    def OnDeactivate(self):
        self._unregister_handlers()

    def OnDblClick(self, node_id):
        # On double-click, jump to the clicked address.
        idaapi.jumpto(self[node_id])

        return True

    def _attach_to_popup(self, action_name):
        idaapi.attach_action_to_popup(self.GetTCustomControl(), None, action_name)

    def OnClick(self, node_id):
        self._current_node_id = node_id
        node_ea = self[node_id]

        self._remove_target_handler.unregister()
        self._disable_source_handler.unregister()
        self._enable_source_handler.unregister()

        if node_ea in self._targets:
            self._remove_target_handler.register()
            self._attach_to_popup(self._remove_target_handler.get_name())

        if node_ea in self._sources:
            if node_ea in self._disabled_sources:
                self._enable_source_handler.register()
                self._attach_to_popup(self._enable_source_handler.get_name())
            else:
                self._disable_source_handler.register()
                self._attach_to_popup(self._disable_source_handler.get_name())

        return False


######################################################################
class LCA(idaapi.plugin_t):
    flags = 0
    comment = "Lowest Common Ancestors"
    help = "Lowest Common Ancestors"
    wanted_name = "Lowest Common Ancestors"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_PROC

    def term(self):
        pass

    def run(self, arg):
        lca_viewer = LCAGraph("My LCA Graph")
        # map(lca_viewer.add_target, [0x004243C8, 0x004243DC, 0x004243E8, 0x004243F0])
        lca_viewer.Show()


def PLUGIN_ENTRY():
    return LCA()