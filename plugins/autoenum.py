import idaapi
import sark
import sark.enum
import idc
import sark.exceptions


class AutoEnum(idaapi.plugin_t):
    flags = 0
    comment = "Automatic Enum Generation"
    help = "Automatic Enum Generation"
    wanted_name = "AutoEnum"
    wanted_hotkey = "Shift+M"

    def init(self):
        self._last_enum = ""
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        enum_name = idc.AskStr(self._last_enum, "Enum Name")
        if enum_name is None:
            return

        if not enum_name:
            enum_name = None

        self._last_enum = enum_name

        const_name = idc.AskStr(None, "Const Name")
        if not const_name:
            return

        const_value = idc.AskLong(0, "Const Value")
        if const_value is None:
            return

        try:
            eid = sark.enum.add_enum(enum_name)
        except sark.exceptions.EnumAlreadyExists:
            yes_no_cancel = idc.AskYN(idaapi.ASKBTN_NO,
                                      "Enum already exists. Modify?\n")
            if yes_no_cancel == idaapi.ASKBTN_CANCEL:
                return

            elif yes_no_cancel == idaapi.ASKBTN_YES:
                eid = sark.enum.get_enum(enum_name)

            else:  # yes_no_cancel == idaapi.ASKBTN_NO:
                return

        sark.enum.add_enum_member(eid, const_name, const_value)


def PLUGIN_ENTRY():
    return AutoEnum()