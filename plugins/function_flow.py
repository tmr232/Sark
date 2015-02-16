import idaapi

from sark.graph import (clear_func,
                        mark_not_reaching_nodes,
                        mark_reaching_nodes,
                        mark_unreachable_nodes,
                        mark_reachable_nodes,
                        mark_exit_nodes,
                        iter_exit_nodes)
from sark.ui import ActionHandler


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


class MarkExits(ActionHandler):
    TEXT = "Exits"

    def _activate(self, ctx):
        clear_func(ctx.cur_ea)
        mark_exit_nodes(ctx.cur_ea)

        idaapi.msg("\n"*2)

        for block in iter_exit_nodes(ctx.cur_ea):
            idaapi.msg("Exit at 0x{:08X}\n".format(block.startEA))


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
            idaapi.attach_action_to_popup(form, popup, MarkExits.get_name(), "Mark/")
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
        MarkExits.register()
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














