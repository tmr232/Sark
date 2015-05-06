from awesome.context import ignored
import sark
import sark.graph
import networkx as nx
import sark.ui
import idc
import idaapi


COLOR_SOURCE = 0x364b00
COLOR_TARGET = 0x601116
COLOR_DISABLED = 0x000673
COLOR_PATH = 0x004773
COLOR_SOURCE_TARGET = 0x634107

PADDING = 1
PAD_WIDTH = 3


def pad(text, padding=PADDING):
    top_bottom = ("\n" * padding) + " "
    right_left = " " * padding * PAD_WIDTH
    return top_bottom + right_left + text + right_left + top_bottom


def remove_target_handler(lca_viewer):
    class RemoveTargetHandler(sark.ui.ActionHandler):
        TEXT = "Remove Target"

        def _activate(self, ctx):
            node_id = lca_viewer.current_node_id
            lca_viewer.remove_target(lca_viewer[node_id])
            lca_viewer.rebuild_graph()
            lca_viewer.Refresh()
            idaapi.msg("[LCA] Target Removed: {}\n".format(idc.Name(lca_viewer[node_id])))


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

            lca_viewer.add_target(func.startEA)
            lca_viewer.rebuild_graph()
            lca_viewer.Refresh()
            lca_viewer.Show()

    return AddFunctionHandler


class LCAGraph(idaapi.GraphViewer):
    def __init__(self, title):
        self._title = title
        idaapi.GraphViewer.__init__(self, self._title)

        self._targets = set()
        self._sources = set()

        # This might take a while...
        self._idb_graph = sark.graph.get_idb_graph()

        self._lca_graph = nx.DiGraph()

        self._handlers = [add_function_handler(self),
                          add_address_handler(self)]

        self._current_node_id = 0

        self._disabled_sources = set()

        self._remove_target_handler = remove_target_handler(self)
        self._enable_source_handler = enable_source_handler(self)
        self._disable_source_handler = disable_source_handler(self)

        self._node_ids = {}


    @property
    def current_node_id(self):
        return self._current_node_id

    def OnGetText(self, node_id):
        return pad(idc.Name(self[node_id]))

    def _register_handlers(self):
        for handler in self._handlers:
            handler.register()

    def Show(self):
        if not idaapi.GraphViewer.Show(self):
            return False

        self._register_handlers()
        self.color_nodes()
        return True

    def disable_source(self, source):
        self._disabled_sources.add(source)

    def enable_source(self, source):
        self._disabled_sources.remove(source)

    def add_target(self, target):
        if target not in self._idb_graph.node:
            idaapi.msg("[LCA] Target {} not in IDB graph. Cannot add.\n".format(idc.Name(target)))
            raise KeyError("Target {} not in IDB graph.".format(idc.Name(target)))

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

    def _set_node_bg_color(self, node_id, bg_color):
        node_info = idaapi.node_info_t()
        node_info.bg_color = bg_color
        self.SetNodeInfo(node_id, node_info, idaapi.NIF_BG_COLOR)

    def color_nodes(self):
        self.clear_nodes()
        for node_id, node_ea in enumerate(self):
            if node_ea in self._targets and node_ea in self._sources:
                self._set_node_bg_color(node_id, COLOR_SOURCE_TARGET)

            elif node_ea in self._disabled_sources:
                self._set_node_bg_color(node_id, COLOR_DISABLED)

            elif node_ea in self._targets:
                self._set_node_bg_color(node_id, COLOR_TARGET)

            elif node_ea in self._sources:
                self._set_node_bg_color(node_id, COLOR_SOURCE)


    def clear_nodes(self):
        for node_id in xrange(self.Count()):
            self._set_node_bg_color(node_id, 0xFFFFFFFF)


    def OnRefresh(self):
        self.Clear()

        if self._targets and self._lca_graph is None:
            # This might take a while...
            self.rebuild_graph()

        node_ids = {node: self.AddNode(node) for node in self._lca_graph.nodes_iter()}

        self._node_ids = node_ids

        for frm, to in self._lca_graph.edges_iter():
            self.AddEdge(node_ids[frm], node_ids[to])

        self.color_nodes()

        return True

    def OnActivate(self):
        # Refresh on every activation to make sure the names are up to date.
        self.Refresh()
        self._register_handlers()
        self.color_nodes()
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
        self.color_nodes()
        self._current_node_id = node_id
        node_ea = self[node_id]

        self._remove_target_handler.unregister()
        self._disable_source_handler.unregister()
        self._enable_source_handler.unregister()

        if node_ea in self._targets:
            self._remove_target_handler.register()
            self._attach_to_popup(self._remove_target_handler.get_name())

            for ea in nx.ancestors(self._lca_graph, node_ea):
                if ea not in self._targets and ea not in self._sources:
                    self._set_node_bg_color(self._node_ids[ea], COLOR_PATH)

        if node_ea in self._sources:
            if node_ea in self._disabled_sources:
                self._enable_source_handler.register()
                self._attach_to_popup(self._enable_source_handler.get_name())
            else:
                self._disable_source_handler.register()
                self._attach_to_popup(self._disable_source_handler.get_name())

                for ea in nx.descendants(self._lca_graph, node_ea):
                    if ea not in self._targets and ea not in self._sources:
                        self._set_node_bg_color(self._node_ids[ea], COLOR_PATH)

        return False


def lca_viewer_starter(lca_plugin):
    class LCAViewerStarter(sark.ui.ActionHandler):
        TEXT = "LCA Graph"
        TOOLTIP = "Show an interactive lowest-common-ancestors graph."

        def _activate(self, ctx):
            lca_plugin.show_graph()

    return LCAViewerStarter


def idaview_add_target_handler(lca_plugin):
    class IDAViewAddTargetHandler(sark.ui.ActionHandler):
        TEXT = "Add LCA Target"

        def _activate(self, ctx):
            if lca_plugin._lca_viewer:
                with ignored(KeyError):
                    lca_plugin._lca_viewer.add_target(ctx.cur_ea)
                    lca_plugin._lca_viewer.rebuild_graph()
                    idaapi.msg("[LCA] Target Added: {}\n".format(idc.Name(ctx.cur_ea)))

    return IDAViewAddTargetHandler


def idaview_hooks(idaview_handler):
    class Hooks(idaapi.UI_Hooks):
        def finish_populating_tform_popup(self, form, popup):
            if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
                idaapi.attach_action_to_popup(form, popup, idaview_handler.get_name(), "")

    return Hooks


class LCA(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Lowest Common Ancestors"
    help = "Lowest Common Ancestors"
    wanted_name = "Lowest Common Ancestors"
    wanted_hotkey = ""

    def init(self):
        self._lca_viewer = None

        self._lca_starter = lca_viewer_starter(self)
        self._lca_starter.register()
        idaapi.attach_action_to_menu("View/Graph Overview", self._lca_starter.get_name(), idaapi.SETMENU_APP)

        self._idaview_handler  = idaview_add_target_handler(self)
        self._idaview_handler.register()
        self._hooks = idaview_hooks(self._idaview_handler)()
        self._hooks.hook()

        return idaapi.PLUGIN_KEEP

    def term(self):
        self._lca_starter.unregister()
        self._idaview_handler.unregister()
        self._hooks.unhook()

    def show_graph(self):
        if self._lca_viewer is None:
            self._lca_viewer = LCAGraph("LCA Graph")
        self._lca_viewer.Show()


    def run(self, arg):
        self.show_graph()


def PLUGIN_ENTRY():
    return LCA()