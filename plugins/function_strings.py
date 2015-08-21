from awesome.context import ignored
import idaapi
import idc
import sark


def show_function_strings(function):
    idaapi.msg("\n\nString References in {}:0x{:08X}\n".format(function.name, function.startEA))
    idaapi.msg("From          To            String\n")

    for xref in function.xrefs_from:
        with ignored(sark.exceptions.SarkNoString):
            string = sark.get_string(xref.to)
            # Trim the string for easier display
            string = string[:100]

            idaapi.msg("0x{:08X}    0x{:08X}    {}\n".format(xref.frm, xref.to, repr(string)))


def show_current_function_strings():
    try:
        function = sark.Function(idc.here())
        show_function_strings(function)

    except sark.exceptions.SarkNoFunction:
        idaapi.msg("[FunctionStrings] No function at 0x{:08X}.\n".format(idc.here()))


def show_highlighted_function_strings():
    identifier = idaapi.get_highlighted_identifier()
    if not identifier:
        return

    try:
        function = sark.Function(name=identifier)
        show_function_strings(function)

    except sark.exceptions.SarkNoFunction:
        idaapi.msg("[FunctionStrings] {!r} is not a function.\n".format(identifier))


class FunctionStrings(idaapi.plugin_t):
    flags = 0
    comment = "Show Function Strings"
    help = "Show all strings references by the function."
    wanted_name = "FunctionStrings"
    wanted_hotkey = ""

    def init(self):
        self.hotkeys = []
        self.hotkeys.append(idaapi.add_hotkey("Alt+9", show_current_function_strings))
        self.hotkeys.append(idaapi.add_hotkey("Ctrl+Alt+9", show_highlighted_function_strings))
        return idaapi.PLUGIN_KEEP

    def term(self):
        for hotkey in self.hotkeys:
            idaapi.del_hotkey(hotkey)

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return FunctionStrings()
