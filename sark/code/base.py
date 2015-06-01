import collections
import string

import idaapi
import idc
import idautils

from ..core import get_func
from .. import exceptions


NAME_VALID_CHARS = string.ascii_letters + string.digits + "?_:"

DTYP_TO_SIZE = {
    idaapi.dt_byte: 1,
    idaapi.dt_word: 2,
    idaapi.dt_dword: 4,
    idaapi.dt_float: 4,
    idaapi.dt_double: 8,
    idaapi.dt_qword: 8,
    idaapi.dt_byte16: 16,
    idaapi.dt_fword: 6,
    idaapi.dt_3byte: 3,
    idaapi.dt_byte32: 32,
    idaapi.dt_byte64: 64,
}


def dtyp_to_size(dtyp):
    return DTYP_TO_SIZE[dtyp]


def is_ea_call(ea):
    inst = idautils.DecodeInstruction(ea)
    feature = inst.get_canon_feature()
    return feature & idaapi.CF_CALL


def get_register_info(reg_name):
    ri = idaapi.reg_info_t()
    success = idaapi.parse_reg_name(reg_name, ri)
    if not success:
        raise exceptions.SarkInvalidRegisterName("No register named {!r}".format(reg_name))
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


def operand_has_displacement(operand):
    if operand.type in (idaapi.o_phrase, idaapi.o_displ):
        return True

    return False


def operand_get_displacement(operand):
    return operand.addr


def is_same_function(ea1, ea2):
    try:
        if get_func(ea1).startEA == get_func(ea2).startEA:
            return True
    except:
        pass

    return False


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