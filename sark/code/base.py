import collections
import string

import idaapi
import idc
import idautils

from ..core import get_func, get_native_size
from .. import exceptions

NAME_VALID_CHARS = string.ascii_letters + string.digits + "?_:"

DTYPE_TO_SIZE = {
    idaapi.dt_byte: 1,
    idaapi.dt_word: 2,
    idaapi.dt_dword: 4,
    idaapi.dt_float: 4,
    idaapi.dt_double: 8,
    idaapi.dt_qword: 8,
    idaapi.dt_byte16: 16,
    idaapi.dt_fword: 6,
    idaapi.dt_byte32: 32,
    idaapi.dt_byte64: 64,
}


def dtype_to_size(dtyp):
    if dtyp == idaapi.dt_tbyte:
        # This can't be put in the dict as it depends on the current processor
        # and may change during runtime.
        return idaapi.ph_get_tbyte_size()

    return DTYPE_TO_SIZE[dtyp]


def is_ea_call(ea):
    inst = idautils.DecodeInstruction(ea)
    feature = inst.get_canon_feature()
    return feature & idaapi.CF_CALL


def get_register_info(reg_name):
    ri = idaapi.reg_info_t()
    if idaapi.IDA_SDK_VERSION >= 750:
        success = idaapi.parse_reg_name(ri, reg_name)
    else:
        success = idaapi.parse_reg_name(reg_name, ri)
    if not success:
        raise exceptions.SarkInvalidRegisterName("No register named {!r}".format(reg_name))
    return ri


def get_register_id(reg_name):
    return get_register_info(reg_name).reg


def get_register_size(reg_name):
    return get_register_info(reg_name).size


def get_register_name(reg_id, size=None):
    if size is None:
        size = get_native_size()
    return idaapi.get_reg_name(reg_id, size)


def operand_has_displacement(operand):
    if operand.type in (idaapi.o_phrase, idaapi.o_displ):
        return True

    return False


def operand_get_displacement(operand):
    return operand.addr


def is_same_function(ea1, ea2):
    try:
        if get_func(ea1).start_ea == get_func(ea2).start_ea:
            return True
    except:
        pass

    return False


Selection = collections.namedtuple("Selection", "start end")


def get_selection(always=True):
    start = idc.read_selection_start()
    end = idc.read_selection_end()

    if idaapi.BADADDR in (start, end):
        if not always:
            raise exceptions.SarkNoSelection()

        ea = idc.here()
        start = idaapi.get_item_head(ea)
        end = idaapi.get_item_end(ea)

    return Selection(start, end)


def get_highlighted_identifier():
    thing = idaapi.get_highlight(idaapi.get_current_viewer())
    if thing and thing[1]:
        return thing[0]

def format_name(name):
    try:
        return "".join(char if char in NAME_VALID_CHARS else "_" for char in name)
    except:
        return ""

def demangle(name, disable_mask=0):
    demangled_name = idaapi.demangle_name(name, disable_mask, idaapi.DQT_FULL)
    if demangled_name:
        return demangled_name
    return name


def get_offset_name(ea):
    # Try and get the function name
    try:
        func = get_func(ea)
        name = idaapi.get_ea_name(func.start_ea)
        name = demangle(name, 0x60) # MNG_NOTYPE | MNG_NORETTYPE
        if name:
            offset = ea - func.start_ea
            if offset:
                return '{}+{:X}'.format(name, offset)
            return name
    except exceptions.SarkNoFunction:
        pass

    # If that failed, use the segment name instead.
    segment = idaapi.getseg(ea)
    name = idaapi.get_segm_name(segment)
    offset_format = '{{:0{}X}}'.format(get_native_size() * 2)
    ea_text = offset_format.format(ea)
    if name:
        return '{}:{}'.format(name, ea_text)

    # Nothing found, simply return the address
    return ea_text
