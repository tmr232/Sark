import idaapi
import code
import idc
from code.data import read_ascii_string


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
        function = code.Function(idc.here())

        print "String References in {}:0x{:08X}".format(function.name, function.startEA)
        print "From          To            String"

        for line in function.lines:
            for ea in line.drefs_from:
                if idaapi.isCode(idaapi.getFlags(ea)):
                    continue
                string = read_ascii_string(ea, max_length=100)
                if not code.core.is_string_printable(string):
                    continue

                print "0x{:08X}    0x{:08X}    {}".format(line.ea, ea, repr(string))


def PLUGIN_ENTRY():
    return FunctionStrings()