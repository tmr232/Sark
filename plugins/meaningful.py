import idaapi
import sark
import idc
import sark.ui


class NoString(Exception):
    pass


class NoName(Exception):
    pass


def get_string(ea):
    string_type = idc.GetStringType(ea)

    if string_type is None:
        raise NoString("No string at 0x{:08X}".format(ea))

    string = idc.GetString(ea, strtype=string_type)

    if not string:
        raise NoString("No string at 0x{:08X}".format(ea))

    return string


def get_name(ea):
    name = None

    if not sark.Line(ea).has_name:
        raise NoName("No non-trivial name for 0x{:08X}".format(ea))

    try:
        function = sark.Function(ea)
        if function.ea == ea:
            name = function.demangled
    except:
        pass

    if not name:
        name = idc.Name(ea)

    if not name:
        raise NoName("No named for address 0x{:08X}".format(ea))

    return name


def show_meaningful_in_function(function):
    idaapi.msg("\n\nMeaningful References in {!r} : 0x{:08X}\n".format(function.demangled, function.startEA))
    idaapi.msg("Type    Usage         Address       Object\n")
    idaapi.msg("------------------------------------------\n")

    for xref in function.xrefs_from:
        if xref.type.is_code:
            try:
                name = get_name(xref.to)
            except NoName:
                continue

            idaapi.msg("code    0x{:08X}    0x{:08X}    {}\n".format(xref.frm, xref.to, name))

        else:
            try:
                string = get_string(xref.to)
            except NoString:
                continue

            # Trim the string for easier display
            string = string[:100]

            idaapi.msg("str     0x{:08X}    0x{:08X}    {}\n".format(xref.frm, xref.to, repr(string)))

    idaapi.msg("\n\n")


def show_current_function_meaningful():
    try:
        function = sark.Function(idc.here())
        show_meaningful_in_function(function)

    except sark.exceptions.SarkNoFunction:
        idaapi.msg("[FunctionStrings] No function at 0x{:08X}.\n".format(idc.here()))


def show_highlighted_function_meaningful():
    line = sark.Line()
    for xref in line.xrefs_from:
        try:
            if xref.type.is_flow:
                continue

            function = sark.Function(xref.to)
            show_meaningful_in_function(function)

        except sark.exceptions.SarkNoFunction:
            pass


class Meaningful(idaapi.plugin_t):
    flags = 0
    comment = "Show meaningful information"
    help = "Show strings and named xrefs"
    wanted_name = "Meaningful"
    wanted_hotkey = ""

    def init(self):
        self.hotkeys = []
        self.hotkeys.append(idaapi.add_hotkey("Alt+0", show_current_function_meaningful))
        self.hotkeys.append(idaapi.add_hotkey("Ctrl+Alt+0", show_highlighted_function_meaningful))
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return Meaningful()
