import idaapi
import idc
import sark


class FunctionStrings(idaapi.plugin_t):
    flags = 0
    comment = "Show Function Strings"
    help = "Show all strings references by the function."
    wanted_name = "FunctionStrings"
    wanted_hotkey = "Alt+9"

    def init(self):
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        function = sark.Function(idc.here())

        idaapi.msg("\n\nString References in {}:0x{:08X}\n".format(function.name, function.startEA))
        idaapi.msg("From          To            String\n")

        for xref in function.xrefs_from:
            if xref.type.is_code:
                continue

            string_type = idc.GetStringType(xref.to)

            if string_type is None:
                continue

            string = idc.GetString(xref.to, strtype=string_type)

            if not string:
                continue

            # Trim the string for easier display
            string = string[:100]

            idaapi.msg("0x{:08X}    0x{:08X}    {}\n".format(xref.frm, xref.to, repr(string)))


def PLUGIN_ENTRY():
    return FunctionStrings()