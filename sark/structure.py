from . import exceptions
import idaapi
from . import code
import idautils
import idc
from collections import namedtuple, defaultdict
import operator
from .code import lines, dtyp_to_size

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
    sid = idc.GetStrucIdByName(name)
    if sid != 0xFFFFFFFF:
        # The struct already exists.
        raise exceptions.SarkStructAlreadyExists()

    sid = idc.AddStrucEx(-1, name, 0)
    if sid == 0xFFFFFFFF:
        raise exceptions.SarkStructCreationFailed()

    return sid


def get_struct(name):
    sid = idc.GetStrucIdByName(name)
    if sid == 0xFFFFFFFF:
        raise exceptions.SarkStructNotFound()

    return sid


def size_to_flags(size):
    return SIZE_TO_TYPE[size] | idc.FF_DATA


def add_struct_member(sid, name, offset, size):
    idaapi.msg("{}, {}\n".format(offset, size))
    failure = idc.AddStrucMember(sid, name, offset, size_to_flags(size), -1, size)

    if failure:
        raise struct_member_error(failure, sid, name, offset, size)


StructOffset = namedtuple("StructOffset", "offset size")
OperandRef = namedtuple("OperandRef", "ea n")


def infer_struct_offsets(start, end, reg_name):
    offsets = set()
    operands = []
    for line in lines(start, end):
        insn = line.insn
        if not insn.has_reg(reg_name):
            continue

        for operand in insn.operands:
            if not operand.has_reg(reg_name):
                continue

            if not operand.has_displacement:
                continue

            offset = operand.displacement
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
    """
    registers = defaultdict(int)
    for line in lines(start, end):
        insn = line.insn

        for operand in insn.operands:

            if not operand.has_displacement:
                continue

            register_name = operand.reg
            registers[register_name] += 1

    return max(registers.iteritems(), key=operator.itemgetter(1))[0]


def offset_name(offset):
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


def create_struct_from_offsets(name, offsets):
    sid = create_struct(name)

    set_struct_offsets(offsets, sid)


def apply_struct(start, end, reg_name, struct_name):
    offsets, operands = infer_struct_offsets(start, end, reg_name)

    sid = get_struct(struct_name)

    for ea, n in operands:
        idc.OpStroff(ea, n, sid)

# TODO: Deal with member types and structs in members.

# TODO: Add proper handling to unions. They are significantly different for IDA, but should be seamless here.
# TODO: First finish regular structs, then go and do unions.

# TODO: Add handling for varstructcs


class StructMemberComments(object):
    def __init__(self, member_t):
        super(StructMemberComments, self).__init__()

        self._member_t = member_t

    @property
    def regular(self):
        return idaapi.get_member_cmt(self._member_t.id, False)

    @regular.setter
    def regular(self, comment):
        idaapi.set_member_cmt(self._member_t, comment, False)
        
    @property
    def repeat(self):
        return idaapi.get_member_cmt(self._member_t.id, True)

    @repeat.setter
    def repeat(self, comment):
        idaapi.set_member_cmt(self._member_t, comment, True)


class StructMember(object):
    def __init__(self, member_t):
        super(StructMember, self).__init__()

        self._member_t = member_t
        self._comments = StructMemberComments(self._member_t)

    @property
    def member_t(self):
        return self._member_t

    @property
    def id(self):
        return self.member_t.id

    @property
    def name(self):
        return idaapi.get_member_name(self.id)

    @name.setter
    def name(self, name):
        idaapi.set_member_name(self.id, name)

    @property
    def fullname(self):
        return idaapi.get_member_fullname(self.id)

    @property
    def start(self):
        if self.is_union:
            return 0

        return self.member_t.soff

    offset = start

    @property
    def end(self):
        # TODO: What to do if it is union?
        return self.member_t.eoff

    @property
    def size(self):
        return idaapi.get_member_size(self.member_t)


    @property
    def is_union(self):
        return self.member_t.unimem()

    @property
    def has_typeinfo(self):
        return self.member_t.has_ti()

    @property
    def comments(self):
        return self._comments


class StructComments(object):
    def __init__(self, sid):
        super(StructComments, self).__init__()
        self._sid = sid

    @property
    def regular(self):
        return idaapi.get_struc_cmt(self._sid, False)

    @regular.setter
    def regular(self, comment):
        idaapi.set_struc_cmt(self._sid, comment, False)

    @property
    def repeat(self):
        return idaapi.get_struc_cmt(self._sid, True)

    @repeat.setter
    def repeat(self, comment):
        idaapi.set_struc_cmt(self._sid, comment, True)


class Struct(object):
    def __init__(self, name=None, sid=None, struc_t=None):
        super(Struct, self).__init__()
        # Make sure only one value is provided
        if len(filter(None, (name, sid, struc_t))) != 1:
            raise TypeError("Provide one of (name, sid, struc_t), and one only.")

        if struc_t is None:
            self._sid = sid or idaapi.get_struc_id(name)
            self._comments = StructComments(self._sid)
            self._struc_t = idaapi.get_struc(self._sid)

        else:
            self._sid = struc_t.id
            self._struc_t = struc_t

    @property
    def sid(self):
        return self._sid

    @property
    def struc_t(self):
        return self._struc_t

    @property
    def name(self):
        return idaapi.get_struc_name(self.sid)

    @name.setter
    def name(self, name):
        idaapi.set_struc_name(self.sid, name)

    @property
    def comments(self):
        return self._comments

    @property
    def size(self):
        return idaapi.get_struc_size(self._sid)

    @property
    def align(self):
        return self.struc_t.get_alignment()

    @align.setter
    def align(self, shift):
        self.struc_t.set_alignment(shift)

    @property
    def is_union(self):
        return self.struc_t.is_union()

    @property
    def is_from_til(self):
        return self.struc_t.from_til()

    @property
    def members(self):
        return (StructMember(self.struc_t.get_member(index)) for index in xrange(self.struc_t.memqty))


def structs():
    for struct_index in xrange(idaapi.get_struc_qty()):
        yield Struct(sid=idaapi.get_struc_by_idx(struct_index))