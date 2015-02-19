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

        idaapi.msg("String References in {}:0x{:08X}\n".format(function.name, function.startEA))
        idaapi.msg("From          To            String\n")

        for line in function.lines:
            for ea in line.drefs_from:
                if idaapi.isCode(idaapi.getFlags(ea)):
                    continue
                string = sark.read_ascii_string(ea, max_length=100)
                if not sark.core.is_string_printable(string):
                    continue

                idaapi.msg("0x{:08X}    0x{:08X}    {}\n".format(line.ea, ea, repr(string)))


def PLUGIN_ENTRY():
    return FunctionStrings()