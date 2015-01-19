import struct
import itertools
import collections
import string

import idaapi
import idc
import idautils
from .core import get_func, get_ea
from . import exceptions
from .core import fix_addresses, iter_find_query, iter_find_string


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
    # TODO: the 4 size is great for MIPS, but there should be a way to tell the actual size from an opcode.
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
        return idautils.XrefsFrom(self.ea)

    @property
    def drefs_from(self):
        return idautils.DataRefsFrom(self.ea)

    @property
    def crefs_from(self):
        return idautils.CodeRefsFrom(self.ea, 1)

    @property
    def xrefs_to(self):
        return idautils.XrefsTo(self.ea)

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
    def name(self, value):
        idc.MakeName(self.startEA, value)

    def __repr__(self):
        return 'Function(name="{}", addr=0x{:08X})'.format(self.name, self.startEA)


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


def undefine(start, end):
    idc.MakeUnknown(start, end - start, idc.DOUNK_SIMPLE)


def range(start, end=None, step=1):
    if end is None:
        end = start
        start = 0

    if cmp(start, end) * step >= 0:
        return

    value = start
    while cmp(start, end) * cmp(value, end) > 0:
        yield value
        value += step


def Bytes(start=None, end=None):
    start, end = fix_addresses(start, end)

    return itertools.imap(idc.Byte, range(start, end))


def Words(start=None, end=None):
    start, end = fix_addresses(start, end)

    return itertools.imap(idc.Word, range(start, end, 2))


def Dwords(start=None, end=None):
    start, end = fix_addresses(start, end)

    return itertools.imap(idc.Dword, range(start, end, 4))


def Qwords(start=None, end=None):
    start, end = fix_addresses(start, end)

    return itertools.imap(idc.Qword, range(start, end, 4))


def bytes_until(byte=0, start=None, end=None):
    return iter(Bytes(start, end).next, byte)


def words_until(word=0, start=None, end=None):
    return iter(Words(start, end).next, word)


def dwords_until(dword=0, start=None, end=None):
    return iter(Dwords(start, end).next, dword)


def Chars(start=None, end=None):
    return itertools.imap(chr, Bytes(start, end))


def chars_until(char='\0', start=None, end=None):
    return iter(Chars(start, end).next, char)


def read_ascii_string(ea, max_length=None):
    if max_length is None:
        end = None
    else:
        end = ea + max_length
    return "".join(chars_until(start=ea, end=end))


def dword_to_bytes(dword):
    return struct.pack(">L", dword)


def read_memory(start, end):
    size = end - start

    dword_count = size // 4
    byte_count = size % 4

    dwords_data = itertools.imap(dword_to_bytes, Dwords(start, start + (dword_count * 4)))
    bytes_data = Chars(end - byte_count, end)

    data = "".join(itertools.chain(dwords_data, bytes_data))

    return data


def ilen(iterator):
    return sum(1 for item in iterator)


def format_name(name):
    try:
        return "".join(char if char in NAME_VALID_CHARS else "_" for char in name)
    except:
        return ""