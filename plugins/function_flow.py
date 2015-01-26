import idaapi
import idc
import networkx as nx
import sark
from sark.ui import ActionHandler


MARKBLOCK_REACHABLE = "markblock:reachable"
MARKBLOCK_UNREACHABLE = "markblock:unreachable"
MARKBLOCK_REACHING = "markblock:reaching"
MARKBLOCK_NOTREACHING = "markblock:notreaching"
MARKBLOCK_CLEAR = "markblock:clear"

COLOR_REACHABLE = 0x66EE11
COLOR_UNREACHABLE = 0x6611EE
COLOR_REACHING = 0x11EE66
COLOR_NOT_REACHING = 0x1166EE
COLOR_SOURCE = 0xEE6611
COLOR_NONE = 0xFFFFFFFF


class MarkReachableNodesHandler(ActionHandler):
    NAME = MARKBLOCK_REACHABLE
    TEXT = "Reachable"
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        clear_func(idc.here())
        mark_reachable_nodes(idc.here())
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MarkUnReachableNodesHandler(ActionHandler):
    NAME = MARKBLOCK_UNREACHABLE
    TEXT = "Unreachable"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        clear_func(idc.here())
        mark_unreachable_nodes(idc.here())
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class MarkReachingNodesHandler(ActionHandler):
    NAME = MARKBLOCK_REACHING
    TEXT = "Reaching"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        clear_func(idc.here())
        mark_reaching_nodes(idc.here())
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class MarkNotReachingNodesHandler(ActionHandler):
    NAME = MARKBLOCK_NOTREACHING
    TEXT = "Not Reaching"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        clear_func(idc.here())
        mark_not_reaching_nodes(idc.here())
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MarkClearHandler(ActionHandler):
    NAME = MARKBLOCK_CLEAR
    TEXT = "Clear"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        clear_func(idc.here())
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class Hooks(idaapi.UI_Hooks):
    def populating_tform_popup(self, form, popup):
        # You can attach here.
        pass

    def finish_populating_tform_popup(self, form, popup):
        # Or here, after the popup is done being populated by its owner.

        if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, MARKBLOCK_REACHABLE, "Mark/")
            idaapi.attach_action_to_popup(form, popup, MARKBLOCK_UNREACHABLE, "Mark/")
            idaapi.attach_action_to_popup(form, popup, MARKBLOCK_REACHING, "Mark/")
            idaapi.attach_action_to_popup(form, popup, MARKBLOCK_NOTREACHING, "Mark/")
            idaapi.attach_action_to_popup(form, popup, MARKBLOCK_CLEAR, "Mark/")




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