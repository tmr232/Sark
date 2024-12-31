from collections import namedtuple, defaultdict
import operator

import idaapi
import idautils
import idc
import ida_typeinf

from . import exceptions
from .code import lines

FF_TYPES = [idc.FF_BYTE, idc.FF_WORD, idc.FF_DWORD, idc.FF_QWORD, idc.FF_OWORD, ]
FF_SIZES = [1, 2, 4, 8, 16, ]

SIZE_TO_TYPE = dict(zip(FF_SIZES, FF_TYPES))

STRUCT_ERROR_MAP = {
    ida_typeinf.TERR_BAD_NAME:
        (exceptions.SarkErrorStructMemberName, "already has member with this name (bad name)"),
    ida_typeinf.TERR_BAD_OFFSET:
        (exceptions.SarkErrorStructMemberOffset, "already has member at this offset"),
    ida_typeinf.TERR_BAD_SIZE:
        (exceptions.SarkErrorStructMemberSize, "bad number of bytes or bad sizeof(type)"),
    ida_typeinf.TERR_BAD_TYPE:
        (exceptions.SarkErrorStructMemberTinfo, "bad typeid parameter"),
    ida_typeinf.TERR_BAD_UNIVAR:
        (exceptions.SarkErrorStructMemberUnivar, "unions can't have variable sized members"),
    ida_typeinf.TERR_BAD_VARLAST:
        (exceptions.SarkErrorStructMemberVarlast, "variable sized member should be the last member in the structure"),
}


def struct_member_error(err, tid, name, offset, size):
    """Create and format a struct member exception.

    Args:
        err: The error value returned from struct member creation
        tid: The type id
        name: The member name
        offset: Memeber offset
        size: Member size

    Returns:
        A ``SarkErrorAddStructMemeberFailed`` derivative exception, with an
        informative message.
    """
    exception, msg = STRUCT_ERROR_MAP[err]
    struct_name = idaapi.get_tid_name(tid)
    return exception(('AddStructMember(struct="{}", member="{}", offset={}, size={}) '
                      'failed: {}').format(
        struct_name,
        name,
        offset,
        size,
        msg
    ))


def create_struct(name):
    """Create a structure.

    Args:
        name: The structure's name

    Returns:
        The sturct ID

    Raises:
        exceptions.SarkStructAlreadyExists: A struct with the same name already exists
        exceptions.SarkCreationFailed:  Struct creation failed
    """
    tid = idaapi.get_named_type_tid(name)
    if tid != idaapi.BADADDR:
        # The struct already exists.
        raise exceptions.SarkStructAlreadyExists("A struct names {!r} already exists.".format(name))

    tid = idaapi.tinfo_t.create_udt(idaapi.BADADDR, name, 0)
    if tid == idaapi.BADADDR:
        raise exceptions.SarkStructCreationFailed("Struct creation failed.")

    return tid


def get_struct(name):
    """Get a struct by it's name.

    Args:
        name: The name of the struct

    Returns:
        The struct's id

    Raises:
        exceptions.SarkStructNotFound: is the struct does not exist.
    """
    tid = idaapi.get_named_type_tid(name)
    if tid == idaapi.BADADDR:
        raise exceptions.SarkStructNotFound()

    return tid


def size_to_flags(size):
    return SIZE_TO_TYPE[size] | idc.FF_DATA


def add_struct_member(tid, name, offset, size):
    failure = idc.add_struc_member(tid, name, offset, size_to_flags(size), -1, size)

    if failure:
        raise struct_member_error(failure, tid, name, offset, size)


StructOffset = namedtuple("StructOffset", "offset size")
OperandRef = namedtuple("OperandRef", "ea n")


def infer_struct_offsets(start, end, reg_name):
    offsets = set()
    operands = []
    for line in lines(start, end):
        for operand in line.insn.operands:
            if not operand.has_reg(reg_name):
                continue

            if not operand.type.has_phrase:
                continue

            if not operand.base:
                continue

            offset = operand.offset
            if offset < 0:
                raise exceptions.InvalidStructOffset(
                    "Invalid structure offset 0x{:08X}, probably negative number.".format(offset))
            size = operand.size
            offsets.add(StructOffset(offset, size))
            operands.append(OperandRef(line.ea, operand.n))

    return offsets, operands


def get_common_register(start, end):
    """Get the register most commonly used in accessing structs.

    Access to is considered for every opcode that accesses memory
    in an offset from a register::

        mov eax, [ebx + 5]

    For every access, the struct-referencing registers, in this case
    `ebx`, are counted. The most used one is returned.

    Args:
        start: The adderss to start at
        end: The address to finish at
    """
    registers = defaultdict(int)
    for line in lines(start, end):
        insn = line.insn

        for operand in insn.operands:

            if not operand.type.has_phrase:
                continue

            if not operand.base:
                continue

            register_name = operand.base
            registers[register_name] += 1

    return max(registers.items(), key=operator.itemgetter(1))[0]


def offset_name(offset):
    """Format an offset into a name."""
    return "offset_{:X}".format(offset.offset)


def set_struct_offsets(offsets, tid):
    for offset in offsets:
        try:
            add_struct_member(tid,
                              offset_name(offset),
                              offset.offset,
                              offset.size)
        except exceptions.SarkErrorStructMemberName:
            # Get the offset of the member with the same name
            existing_offset = idc.get_member_offset(tid, offset_name(offset))
            if offset.offset == existing_offset:
                pass
            else:
                raise
        except exceptions.SarkErrorStructMemberOffset:
            # Get the size of the member at the same offset
            if offset.size == idc.get_member_size(tid, offset.offset):
                # If they are the same, all is well.
                pass


def create_struct_from_offsets(name, offsets):
    tid = create_struct(name)

    set_struct_offsets(offsets, tid)


def apply_struct(start, end, reg_name, struct_name):
    offsets, operands = infer_struct_offsets(start, end, reg_name)

    sid = get_struct(struct_name)

    for ea, n in operands:
        insn = idautils.DecodeInstruction(ea)
        idc.op_stroff(insn, n, sid, 0)


def selection_has_offsets(start, end):
    for line in lines(start, end):
        for operand in line.insn.operands:
            if not operand.type.has_phrase:
                continue
            if not operand.base:
                continue
            return True
    return False
