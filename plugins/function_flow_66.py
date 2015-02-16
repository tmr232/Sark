import idaapi

from sark.graph import (clear_func,
                        mark_not_reaching_nodes,
                        mark_reaching_nodes,
                        mark_unreachable_nodes,
                        mark_reachable_nodes,
                        mark_exit_nodes,
                        iter_exit_nodes)


def mark_reachable():
    ea = idaapi.get_screen_ea()
    clear_func(ea)
    mark_reachable_nodes(ea)


def mark_unreachable():
    ea = idaapi.get_screen_ea()
    clear_func(ea)
    mark_unreachable_nodes(ea)


def mark_reaching():
    ea = idaapi.get_screen_ea()
    clear_func(ea)
    mark_reaching_nodes(ea)


def mark_not_reaching():
    ea = idaapi.get_screen_ea()
    clear_func(ea)
    mark_not_reaching_nodes(ea)


def mark_exists():
    ea = idaapi.get_screen_ea()
    clear_func(ea)
    mark_exit_nodes(ea)

    idaapi.msg("\n" * 2)

    for block in iter_exit_nodes(ea):
        idaapi.msg("Exit at 0x{:08X}\n".format(block.startEA))


def mark_clear():
    ea = idaapi.get_screen_ea()
    clear_func(ea)


class FunctionFlow(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Show Flow in Functions"
    help = "Show code flow inside functions"
    wanted_name = "Function Flow"
    wanted_hotkey = ""

    def init(self):
        idaapi.add_menu_item("View/Mark/", "Reachable", None, 0, mark_reachable, tuple())
        idaapi.add_menu_item("View/Mark/", "Un-Reachable", None, 0, mark_unreachable, tuple())
        idaapi.add_menu_item("View/Mark/", "Reaching", None, 0, mark_reaching, tuple())
        idaapi.add_menu_item("View/Mark/", "Not Reaching", None, 0, mark_not_reaching, tuple())
        idaapi.add_menu_item("View/Mark/", "Exists", None, 0, mark_exists, tuple())
        idaapi.add_menu_item("View/Mark/", "Clear", None, 0, mark_clear, tuple())

        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return FunctionFlow()














