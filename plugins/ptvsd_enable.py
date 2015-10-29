import idaapi
import ptvsd

try:
    # Enable the debugger. Raises exception if called more than once.
    ptvsd.enable_attach(secret="IDA")
except:
    pass


class DebugPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "PTVSD Debug Enable"
    help = "Enable debugging using PTVSD"
    wanted_name = "PTVSD"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return DebugPlugin()