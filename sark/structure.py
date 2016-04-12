from collections import namedtuple, defaultdict
import operator

import idaapi
import idc

from . import exceptions
from .code import lines

FF_TYPES = [idc.FF_BYTE, idc.FF_WORD, idc.FF_DWRD, idc.FF_QWRD, idc.FF_OWRD, ]
FF_SIZES = [1, 2, 4, 8, 16, ]

SIZE_TO_TYPE = dict(zip(FF_SIZES, FF_TYPES))

STRUCT_ERROR_MAP = {
    idc.STRUC_ERROR_MEMBER_NAME:
        (exceptions.SarkErrorStructMemberName, "already has member with this name (bad name)"),
    idc.STRUC_ERROR_MEMBER_OFFSET:
        (exceptions.SarkErrorStructMemberOffset, "already has member at this offset"),
    idc.STRUC_ERROR_MEMBER_SIZE:
        (exceptions.SarkErrorStructMemberSize, "bad number of bytes or bad sizeof(type)"),
    idc.STRUC_ERROR_MEMBER_TINFO:
        (exceptions.SarkErrorStructMemberTinfo, "bad typeid parameter"),
    idc.STRUC_ERROR_MEMBER_STRUCT:
        (exceptions.SarkErrorStructMemberStruct, "bad struct id (the 1st argument)"),
    idc.STRUC_ERROR_MEMBER_UNIVAR:
        (exceptions.SarkErrorStructMemberUnivar, "unions can't have variable sized members"),
    idc.STRUC_ERROR_MEMBER_VARLAST:
        (exceptions.SarkErrorStructMemberVarlast, "variable sized member should be the last member in the structure"),
}


def struct_member_error(err, sid, name, offset, size):
    """Create and format a struct member exception.

    Args:
        err: The error value returned from struct member creation
        sid: The struct id
        name: The member name
        offset: Memeber offset
        size: Member size

    Returns:
        A ``SarkErrorAddStructMemeberFailed`` derivative exception, with an
        informative message.
    """
    exception, msg = STRUCT_ERROR_MAP[err]
    struct_name = idc.GetStrucName(sid)
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
    sid = idc.GetStrucIdByName(name)
    if sid != idaapi.BADADDR:
        # The struct already exists.
        raise exceptions.SarkStructAlreadyExists("A struct names {!r} already exists.".format(name))

    sid = idc.AddStrucEx(-1, name, 0)
    if sid == idaapi.BADADDR:
        raise exceptions.SarkStructCreationFailed("Struct creation failed.")

    return sid


def get_struct(name):
    """Get a struct by it's name.

    Args:
        name: The name of the struct

    Returns:
        The struct's id

    Raises:
        exceptions.SarkStructNotFound: is the struct does not exist.
    """
    sid = idc.GetStrucIdByName(name)
    if sid == idaapi.BADADDR:
        raise exceptions.SarkStructNotFound()

    return sid


def size_to_flags(size):
    return SIZE_TO_TYPE[size] | idc.FF_DATA


def add_struct_member(sid, name, offset, size):
    failure = idc.AddStrucMember(sid, name, offset, size_to_flags(size), -1, size)

    if failure:
        raise struct_member_error(failure, sid, name, offset, size)


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

    return max(registers.iteritems(), key=operator.itemgetter(1))[0]


def offset_name(offset):
    """Format an offset into a name."""
    return "offset_{:X}".format(offset.offset)


def set_struct_offsets(offsets, sid):
    for offset in offsets:
        try:
            add_struct_member(sid,
                              offset_name(offset),
                              offset.offset,
                              offset.size)
        except exceptions.SarkErrorStructMemberName:
            # Get the offset of the member with the same name
            existing_offset = idc.GetMemberOffset(sid, offset_name(offset))
            if offset.offset == existing_offset:
                pass
            else:
                raise
        except exceptions.SarkErrorStructMemberOffset:
            # Get the size of the member at the same offset
            if offset.size == idc.GetMemberSize(sid, offset.offset):
                # If they are the same, all is well.
                pass


def create_struct_from_offsets(name, offsets):
    sid = create_struct(name)

    set_struct_offsets(offsets, sid)


def apply_struct(start, end, reg_name, struct_name):
    offsets, operands = infer_struct_offsets(start, end, reg_name)

    sid = get_struct(struct_name)

    for ea, n in operands:
        idc.OpStroff(ea, n, sid)


def selection_has_offsets(start, end):
    for line in lines(start, end):
        for operand in line.insn.operands:
            if not operand.type.has_phrase:
                continue
            if not operand.base:
                continue
            return True
    return False
