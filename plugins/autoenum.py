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


def get_common_value(desired=None):
    values = defaultdict(int)
    for line in sark.lines(*sark.get_selection()):
        for operand in line.insn.operands:
            if operand.type.is_imm:
                if desired is not None:
                    if desired == operand.imm:
                        return desired
                values[operand.imm] += 1

            elif operand.type.is_displ or operand.type.is_phrase:
                if desired is not None:
                    if desired == operand.addr:
                        return desired
                values[operand.addr] += 1

    # Ignore 0 as it is usually not interesting
    values[0] = 0
    # Get the most common value
    common_value = max(values.iteritems(), key=lambda x: x[1])[0]
    return common_value


def const_name(enum, value):
    return "{}_{:X}h".format(enum.name.upper(), value)


def rename_immediate():
    highlighted = idaapi.get_highlighted_identifier()
    try:
        desired = int(highlighted, 0)
    except (ValueError, TypeError):
        desired = None
    value = idc.AskLong(get_common_value(desired), "Const Value")
    if value is None:
        return

    name = idc.AskStr("", "Constant Name")
    if name is None:
        return

    try:
        enum = sark.Enum('GlobalConstants')
    except sark.exceptions.EnumNotFound:
        enum = sark.add_enum('GlobalConstants')

    enum.members.add(name, value)
    apply_enum_by_name(enum, name)


class RenameImmediateHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        try:
            rename_immediate()
        except:
            import traceback
            traceback.print_exc()

        return 1

    def update(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class AutoEnumHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        try:
            rename_immediate()
        except:
            import traceback
            traceback.print_exc()

        return 1

    def update(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class AutoEnum(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Automatic Enum Generation"
    help = "Automatic Enum Generation"
    wanted_name = "AutoEnum"
    wanted_hotkey = ""

    def init(self):
        self._last_enum = ""

        self.rename_action_desc = idaapi.action_desc_t('AutoEnum:RenameImmediate',
                                                       'Rename immediate value',
                                                       RenameImmediateHandler(),
                                                       'Ctrl+Shift+M',
                                                       'Rename immediate value',
                                                       -1)
        idaapi.register_action(self.rename_action_desc)

        self.autoenum_action_desc = idaapi.action_desc_t('AutoEnum:AutoEnum',
                                                         'Automatically create enum',
                                                         AutoEnumHandler(),
                                                         'Shift+M',
                                                         'Automatically create enum',
                                                         -1)
        idaapi.register_action(self.autoenum_action_desc)

        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.unregister_action(self.autoenum_action_desc.name)
        idaapi.unregister_action(self.rename_action_desc.name)

    def run(self, arg):
        pass

    def autoenum(self):
        common_value = get_common_value()

        enum_name = idc.AskStr(self._last_enum, "Enum Name")
        if enum_name is None:
            return

        if not enum_name:
            enum_name = None

        self._last_enum = enum_name

        # Can't ask with negative numbers.
        if common_value >> ((8 * sark.core.get_native_size()) - 1):
            common_value = 0

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
