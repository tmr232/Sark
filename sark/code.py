import collections
import string
import itertools
import idaapi

import idc

import idautils
from .core import get_func, get_ea
from . import exceptions
from .core import fix_addresses, set_name


NAME_VALID_CHARS = string.ascii_letters + string.digits + "?_:"


def iter_function_lines(func_ea):
    for line in idautils.FuncItems(get_ea(func_ea)):
        yield Line(line)


def is_ea_call(ea):
    inst = idautils.DecodeInstruction(ea)
    feature = inst.get_canon_feature()
    return feature & idaapi.CF_CALL


def get_register_info(reg_name):
    ri = idaapi.reg_info_t()
    success = idaapi.parse_reg_name(reg_name, ri)
    if not success:
        raise exceptions.SarkInvalidRegisterName()
    return ri


def get_register_id(reg_name):
    return get_register_info(reg_name).reg


def get_register_size(reg_name):
    return get_register_info(reg_name).size


def is_reg_in_operand(operand, reg):
    if not isinstance(reg, int):
        reg = get_register_id(reg)

    if operand.type == idaapi.o_reg:
        if operand.reg == reg:
            return True

    # NOTE: This works for MIPS but was not tested for other archs.
    elif operand.type == idaapi.o_displ:
        if operand.reg == reg:
            return True

    elif operand.type == idaapi.o_phrase:
        if operand.reg == reg:
            return True

    return False


def is_reg_in_inst(inst, reg_name):
    reg = get_register_id(reg_name)

    return any(is_reg_in_operand(operand, reg) for operand in inst.Operands)


def get_register_name(reg_id, size=4):
    return idaapi.get_reg_name(reg_id, size)


def operand_has_displacement(opcode):
    if opcode.type in (idaapi.o_phrase, idaapi.o_displ):
        return True

    return False


def operand_get_displacement(opcode):
    return opcode.addr


def is_same_function(ea1, ea2):
    try:
        if get_func(ea1).startEA == get_func(ea2).startEA:
            return True
    except:
        pass

    return False


class Xref(object):
    def __init__(self, xref):
        for attr in [ 'frm', 'to', 'iscode', 'user' ]:
            setattr(self, attr, getattr(xref, attr))

        self._type = XrefType(xref.type)

    @property
    def type(self):
        return self._type


class XrefType(object):
    TYPES = {
        0x00: 'Data_Unknown',
        0x01: 'Data_Offset',
        0x02: 'Data_Write',
        0x03: 'Data_Read',
        0x04: 'Data_Text',
        0x05: 'Data_Informational',
        0x10: 'Code_Far_Call',
        0x11: 'Code_Near_Call',
        0x12: 'Code_Far_Jump',
        0x13: 'Code_Near_Jump',
        0x14: 'Code_User',
        0x15: 'Ordinary_Flow'
    }

    def __init__(self, type_):
        self._type = type_

    @property
    def name(self):
        return self.TYPES[self._type]

    def __repr__(self):
        return self.name

    @property
    def is_code(self):
        return self._type & 0x10

    @property
    def is_data(self):
        return not self.is_code

    @property
    def is_unknown(self):
        return self._type == idaapi.fl_U

    @property
    def is_offset(self):
        return self._type == idaapi.dr_O

    @property
    def is_write(self):
        return self._type == idaapi.dr_W

    @property
    def is_read(self):
        return self._type == idaapi.dr_R

    @property
    def is_text(self):
        return self._type == idaapi.dr_T

    @property
    def is_info(self):
        return self._type == idaapi.dr_I

    @property
    def is_far_call(self):
        return self._type == idaapi.fl_CF

    @property
    def is_near_call(self):
        return self._type == idaapi.fl_CN

    @property
    def is_far_jump(self):
        return self._type == idaapi.fl_JF

    @property
    def is_near_jump(self):
        return self._type == idaapi.fl_JN

    @property
    def is_user(self):
        return self._type == idaapi.fl_U

    @property
    def is_flow(self):
        return self._type == idaapi.fl_F

    @property
    def is_call(self):
        return self.is_far_call or self.is_near_call

    @property
    def is_jump(self):
        return self.is_far_jump or self.is_near_jump


class Line(object):
    def __init__(self, ea):
        self._ea = idaapi.get_item_head(ea)

    @property
    def ea(self):
        return self._ea

    @property
    def disasm(self):
        return idc.GetDisasm(self.ea)

    def __repr__(self):
        return "[{:08X}]    {}".format(self.ea, self.disasm)

    @property
    def xrefs_from(self):
        return map(Xref, idautils.XrefsFrom(self.ea))

    @property
    def drefs_from(self):
        return idautils.DataRefsFrom(self.ea)

    @property
    def crefs_from(self):
        return idautils.CodeRefsFrom(self.ea, 1)

    @property
    def xrefs_to(self):
        return map(Xref, idautils.XrefsTo(self.ea))

    @property
    def drefs_to(self):
        return idautils.DataRefsTo(self.ea)

    @property
    def crefs_to(self):
        return idautils.CodeRefsTo(self.ea, 1)

    @property
    def size(self):
        return idaapi.get_item_size(self.ea)

    @property
    def is_call(self):
        return is_ea_call(self.ea)

    @property
    def name(self):
        return idc.Name(self.ea)

    @name.setter
    def name(self, value):
        idc.MakeName(self.ea, value)

    @property
    def inst(self):
        return idautils.DecodeInstruction(self.ea)

    @property
    def color(self):
        return idc.GetColor(self.ea, idc.CIC_ITEM)

    @color.setter
    def color(self, color):
        if color is None:
            color = 0xFFFFFFFF

        idc.SetColor(self.ea, idc.CIC_ITEM, color)

    @property
    def anterior_comment(self):
        lines = (idc.LineA(self._ea, index) for index in itertools.count())
        return "\n".join(iter(lines.next, None))

    @anterior_comment.setter
    def anterior_comment(self, value):
        idaapi.add_long_cmt(self._ea, True, value)


def iter_lines(start=None, end=None):
    start, end = fix_addresses(start, end)

    item = idaapi.get_item_head(start)
    while item < end:
        yield Line(item)
        item += idaapi.get_item_size(item)


class Function(object):
    def __init__(self, ea):
        self._func = get_func(ea)

    @property
    def lines(self):
        return iter_function_lines(self._func)

    @property
    def startEA(self):
        return self._func.startEA

    @property
    def endEA(self):
        return self._func.endEA

    @property
    def xrefs_to(self):
        return idautils.XrefsTo(self.startEA)

    @property
    def drefs_to(self):
        return idautils.DataRefsTo(self.startEA)

    @property
    def crefs_to(self):
        return idautils.CodeRefsTo(self.startEA, 1)

    @property
    def name(self):
        return idc.Name(self.startEA)

    @name.setter
    def name(self, name):
        self.set_name(name)

    def set_name(self, name, anyway=False):
        set_name(self.startEA, name, anyway=anyway)

    def __repr__(self):
        return 'Function(name="{}", addr=0x{:08X})'.format(self.name, self.startEA)

    @property
    def comment(self):
        return idaapi.get_func_cmt(self._func, False)

    @comment.setter
    def comment(self, value):
        idaapi.set_func_cmt(self._func, value, False)


Selection = collections.namedtuple("Selection", "start end")


def get_selection(always=True):
    start = idc.SelStart()
    end = idc.SelEnd()

    if idaapi.BADADDR in (start, end):
        if not always:
            raise exceptions.SarkNoSelection()

        ea = idc.here()
        start = idaapi.get_item_head(ea)
        end = idaapi.get_item_end(ea)

    return Selection(start, end)


def format_name(name):
    try:
        return "".join(char if char in NAME_VALID_CHARS else "_" for char in name)
    except:
        return ""