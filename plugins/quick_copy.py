import idaapi
import clipboard
import sark


def message(*messages):
    for msg in messages:
        for line in msg.splitlines():
            idaapi.msg("[QuickCopy] {}\n".format(line))


def copy_current_address():
    start, end = sark.get_selection()
    clipboard.copy("0x{:08X}".format(start))


def copy_current_file_offset():
    """Get the file-offset mapped to the current address."""
    start, end = sark.get_selection()

    try:
        file_offset = sark.core.get_fileregion_offset(start)
        clipboard.copy("0x{:08X}".format(file_offset))

    except sark.exceptions.NoFileOffset:
        message("The current address cannot be mapped to a valid offset of the input file.")


def copy_current_selection():
    start, end = sark.get_selection()
    buffer = sark.data.read_memory(start, end)
    clipboard.copy(buffer.encode("hex-bytes"))


class QuickCopy(idaapi.plugin_t):
    flags = 0
    comment = "Quickly copy addresses and instructions"
    help = "Quickly copy addresses and instructions"
    wanted_name = "Quick Copy"
    wanted_hotkey = ""

    def init(self):
        self.hotkeys = []
        self.hotkeys.append(idaapi.add_hotkey("Ctrl+Alt+C", copy_current_address))
        self.hotkeys.append(idaapi.add_hotkey("Ctrl+Alt+C+O", copy_current_file_offset))
        self.hotkeys.append(idaapi.add_hotkey("Ctrl+Shift+C", copy_current_selection))
        return idaapi.PLUGIN_KEEP

    def term(self):
        for hotkey in self.hotkeys:
            idaapi.del_hotkey(hotkey)

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return QuickCopy()
