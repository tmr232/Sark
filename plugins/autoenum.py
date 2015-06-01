from collections import defaultdict
import idaapi
import sark
import idc
import sark.exceptions


def apply_enum_by_name(enum, member_name):
    member_value = enum.members[member_name].value
    for line in sark.lines(*sark.get_selection()):
        for operand in line.insn.operands:
            if operand.type.is_imm:
                if operand.imm == member_value:
                    idc.OpEnumEx(line.ea, operand.n, enum.eid, enum.members[member_name].serial)

            elif operand.type.is_displ or operand.type.is_phrase:
                if operand.addr == member_value:
                    idc.OpEnumEx(line.ea, operand.n, enum.eid, enum.members[member_name].serial)


def get_common_value():
    values = defaultdict(int)
    for line in sark.lines(*sark.get_selection()):
        for operand in line.insn.operands:
            if operand.type.is_imm:
                values[operand.imm] += 1

            elif operand.type.is_displ or operand.type.is_phrase:
                values[operand.addr] += 1

    # Ignore 0 as it is usually not interesting
    values[0] = 0
    # Get the most common value
    common_value = max(values.iteritems(), key=lambda x: x[1])[0]
    return common_value


def const_name(enum, value):
    return "{}_{:X}h".format(enum.name.upper(), value)


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
        common_value = get_common_value()

        enum_name = idc.AskStr(self._last_enum, "Enum Name")
        if enum_name is None:
            return

        if not enum_name:
            enum_name = None

        self._last_enum = enum_name

        const_value = idc.AskLong(common_value, "Const Value")
        if const_value is None:
            return

        modify = True

        try:
            enum = sark.add_enum(enum_name)

        except sark.exceptions.EnumAlreadyExists:
            enum = sark.Enum(enum_name)
            yes_no_cancel = idc.AskYN(idaapi.ASKBTN_NO,
                                      "Enum already exists. Modify?\n")
            if yes_no_cancel == idaapi.ASKBTN_CANCEL:
                return

            elif yes_no_cancel == idaapi.ASKBTN_YES:
                modify = True

            else:  # yes_no_cancel == idaapi.ASKBTN_NO:
                modify = False


        member_name = const_name(enum, const_value)

        if modify:

            try:
                enum.members.add(member_name, const_value)
            except sark.exceptions.SarkErrorAddEnumMemeberFailed as ex:
                idaapi.msg("[AutoEnum] Adding enum member failed: {}.".format(ex.message))


        else:
            for member in enum.members:
                if member.value == const_value:
                    member_name = member.name
                    break
                else:
                    return


        # Apply the enum
        apply_enum_by_name(enum, member_name)


def PLUGIN_ENTRY():
    return AutoEnum()