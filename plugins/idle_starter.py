import sys

import idaapi
import idlelib.PyShell


class IdleStarter(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "IDAPython IDLE Starter"
    help = ""
    wanted_name = "IDLE Starter"
    wanted_hotkey = "Ctrl-Alt-6"

    def init(self):
        self._is_running = False
        return idaapi.PLUGIN_KEEP

    def term(self):
        return None

    def run(self, arg):
        if not self._is_running:
            sys.argv.append("-n")
            idlelib.PyShell.main()
            self._is_running = True


def PLUGIN_ENTRY():
    return IdleStarter()