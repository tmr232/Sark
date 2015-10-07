import idaapi
import idc

import sark


def message(*messages):
    for msg in messages:
        for line in msg.splitlines():
            idaapi.msg("[Autostruct] {}\n".format(line))


class AutoStruct(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "AutoStruct struct creator"
    help = "Automagically Create and Apply Structs"
    wanted_name = "AutoStruct"
    wanted_hotkey = "Shift+T"

    def init(self):
        self._prev_struct_name = ""
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        start, end = sark.get_selection()

        if not sark.structure.selection_has_offsets(start, end):
            message('No structure offsets in selection. Operation cancelled.')
            idaapi.warning('No structure offsets in selection. Operation cancelled.')
            return

        struct_name = idc.AskStr(self._prev_struct_name, "Struct Name")
        if not struct_name:
            message("No structure name provided. Operation cancelled.")
            return
        self._prev_struct_name = struct_name

        common_reg = sark.structure.get_common_register(start, end)
        reg_name = idc.AskStr(common_reg, "Register")
        if not reg_name:
            message("No offsets found. Operation cancelled.")
            return

        try:
            offsets, operands = sark.structure.infer_struct_offsets(start, end, reg_name)
        except sark.exceptions.InvalidStructOffset:
            message("Invalid offset found. Cannot create structure.",
                    "Make sure there are no negative offsets in the selection.")
            return

        except sark.exceptions.SarkInvalidRegisterName:
            message("Invalid register name {!r}. Cannot create structs.".format(reg_name))
            return

        try:
            sark.structure.create_struct_from_offsets(struct_name, offsets)
        except sark.exceptions.SarkStructAlreadyExists:
            yes_no_cancel = idc.AskYN(idaapi.ASKBTN_NO,
                                      "Struct already exists. Modify?\n"
                                      "Cancel to avoid applying the struct.")
            if yes_no_cancel == idaapi.ASKBTN_CANCEL:
                return

            elif yes_no_cancel == idaapi.ASKBTN_YES:
                sid = sark.structure.get_struct(struct_name)
                sark.structure.set_struct_offsets(offsets, sid)

            else:  # yes_no_cancel == idaapi.ASKBTN_NO:
                pass

        sark.structure.apply_struct(start, end, reg_name, struct_name)


def PLUGIN_ENTRY():
    return AutoStruct()
