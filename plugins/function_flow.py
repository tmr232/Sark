import idaapi
import idc
import networkx as nx
import sark
from sark.ui import ActionHandler


COLOR_REACHABLE = 0x66EE11
COLOR_UNREACHABLE = 0x6611EE
COLOR_REACHING = 0x11EE66
COLOR_NOT_REACHING = 0x1166EE
COLOR_SOURCE = 0xEE6611
COLOR_NONE = 0xFFFFFFFF


class MarkReachableNodesHandler(ActionHandler):
    TEXT = "Reachable"

    def _activate(self, ctx):
        clear_func(ctx.cur_ea)
        mark_reachable_nodes(ctx.cur_ea)


class MarkUnReachableNodesHandler(ActionHandler):
    TEXT = "Unreachable"

    def _activate(self, ctx):
        clear_func(ctx.cur_ea)
        mark_unreachable_nodes(ctx.cur_ea)

class MarkReachingNodesHandler(ActionHandler):
    TEXT = "Reaching"

    def _activate(self, ctx):
        clear_func(ctx.cur_ea)
        mark_reaching_nodes(ctx.cur_ea)


class MarkNotReachingNodesHandler(ActionHandler):
    TEXT = "Not Reaching"

    def _activate(self, ctx):
        clear_func(ctx.cur_ea)
        mark_not_reaching_nodes(ctx.cur_ea)


class MarkClearHandler(ActionHandler):
    TEXT = "Clear"

    def _activate(self, ctx):
        clear_func(ctx.cur_ea)


class Hooks(idaapi.UI_Hooks):
    def populating_tform_popup(self, form, popup):
        # You can attach here.
        pass

    def finish_populating_tform_popup(self, form, popup):
        # Or here, after the popup is done being populated by its owner.

        if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, MarkReachableNodesHandler.get_name(), "Mark/")
            idaapi.attach_action_to_popup(form, popup, MarkUnReachableNodesHandler.get_name(), "Mark/")
            idaapi.attach_action_to_popup(form, popup, MarkReachingNodesHandler.get_name(), "Mark/")
            idaapi.attach_action_to_popup(form, popup, MarkNotReachingNodesHandler.get_name(), "Mark/")
            idaapi.attach_action_to_popup(form, popup, MarkClearHandler.get_name(), "Mark/")


class FunctionFlow(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Show Flow in Functions"
    help = "Show code flow inside functions"
    wanted_name = "Function Flow"
    wanted_hotkey = ""

    def init(self):
        MarkReachableNodesHandler.register()
        MarkUnReachableNodesHandler.register()
        MarkReachingNodesHandler.register()
        MarkNotReachingNodesHandler.register()
        MarkClearHandler.register()

        self.hooks = Hooks()
        self.hooks.hook()
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return FunctionFlow()


def mark_reachable_nodes(ea):
    graph = sark.get_nx_graph(ea)
    block_ea = sark.get_block_start(ea)
    for descendant in nx.descendants(graph, block_ea):
        sark.codeblock(descendant).color = COLOR_REACHABLE

    sark.codeblock(ea).color = COLOR_SOURCE


def mark_unreachable_nodes(ea):
    graph = sark.get_nx_graph(ea)
    block_ea = sark.get_block_start(ea)
    descendants = nx.descendants(graph, block_ea)
    for block in sark.flowchart(ea):
        if block.startEA not in descendants:
            block.color = COLOR_UNREACHABLE

    sark.codeblock(ea).color = COLOR_SOURCE


def mark_reaching_nodes(ea):
    graph = sark.get_nx_graph(ea)
    graph = graph.reverse()
    block_ea = sark.get_block_start(ea)
    for descendant in nx.descendants(graph, block_ea):
        sark.codeblock(descendant).color = COLOR_REACHING

    sark.codeblock(ea).color = COLOR_SOURCE


def mark_not_reaching_nodes(ea):
    graph = sark.get_nx_graph(ea)
    graph = graph.reverse()
    block_ea = sark.get_block_start(ea)
    reaching = nx.descendants(graph, block_ea)
    for node_ea in graph.nodes_iter():
        if node_ea not in reaching:
            sark.codeblock(node_ea).color = COLOR_NOT_REACHING

    sark.codeblock(ea).color = COLOR_SOURCE


def clear_func(ea):
    for block in sark.flowchart(ea):
        block.color = COLOR_NONE