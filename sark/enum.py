import idaapi
import exceptions
from awesome.context import ignored

ENUM_ERROR_MAP = {
    idaapi.ENUM_MEMBER_ERROR_NAME:
        (exceptions.SarkErrorEnumMemberName, "already have member with this name (bad name)"),
    idaapi.ENUM_MEMBER_ERROR_VALUE:
        (exceptions.SarkErrorEnumMemberValue, "already have 256 members with this value"),
    idaapi.ENUM_MEMBER_ERROR_ENUM:
        (exceptions.SarkErrorEnumMemberEnum, "bad enum id"),
    idaapi.ENUM_MEMBER_ERROR_MASK:
        (exceptions.SarkErrorEnumMemberMask, "bad bmask"),
    idaapi.ENUM_MEMBER_ERROR_ILLV:
        (exceptions.SarkErrorEnumMemberIllv, "bad bmask and value combination (~bmask & value != 0)"),
}


def enum_member_error(err, eid, name, value):
    exception, msg = ENUM_ERROR_MAP[err]
    enum_name = idaapi.get_enum_name(eid)
    return exception(('add_enum_member(enum="{}", member="{}", value={}) '
                      'failed: {}').format(
        enum_name,
        name,
        value,
        msg
    ))


def get_enum(name):
    eid = idaapi.get_enum(name)
    if eid == idaapi.BADADDR:
        raise exceptions.EnumNotFound('Enum "{}" does not exist.'.format(name))
    return eid


def add_enum(name=None, index=idaapi.BADADDR, flags=idaapi.hexflag(), bitfield=False):
    if name is not None:
        with ignored(exceptions.EnumNotFound):
            get_enum(name)
            raise exceptions.EnumAlreadyExists()

    enum = idaapi.add_enum(index, name, flags)

    if enum == idaapi.BADADDR:
        raise exceptions.EnumCreationFailed('Failed creating enum "{}"'.format(name))

    if bitfield:
        idaapi.set_enum_bf(enum, bitfield)

    return enum


def add_enum_member(enum, name, value):
    error = idaapi.add_enum_member(enum, name, value)

    if error:
        raise enum_member_error(error, enum, name, value)


class Enum(object):
    def __init__(self, name=None, enum_id=None):
        # TODO: Make sure only one (name or enum_id) is provided!
        self._eid = enum_id or get_enum(name)

        self._name
        self._width
        self._place
        self._format
        self._signed
        self._bitfield

    @property
    def name(self):
        return idaapi.get_enum_name(self._eid)

    @property
    def width(self):
        return idaapi.get_enum_width(self._eid)

    @property
    def comment(self):
        return idaapi.get_enum_cmt()

    @property
    def basetype(self):
        return idaapi.get_enum_base_type()

    def __len__(self):
        return idaapi.get_enum_size()

    def __getitem__(self, index):
        if index >= len(self):
            raise IndexError()

        return EnumMember(enum_id=self._eid, member_id=idaapi.get_enum_member())


class EnumMember(object):
    def __init__(self):
        self._name
        self._value
        self._mask
        self._mask_name
        self._enum


def iter_bitmasks(eid):
    bitmask = idaapi.get_first_bmask(eid)

    yield bitmask

    while bitmask != 0xFFFFFFFF:
        bitmask = idaapi.get_next_bmask(eid, bitmask)
        yield bitmask


def iter_enum_member_values(eid, bitmask):
    value = idaapi.get_first_enum_member(eid, bitmask)

    yield value
    while value != 0xFFFFFFFF:
        value = idaapi.get_next_enum_member(eid, value, bitmask)
        yield value


def iter_serial_enum_member(eid, value, bitmask):
    cid, serial = idaapi.get_first_serial_enum_member(eid, value, bitmask)
    while cid != idaapi.BADNODE:
        yield cid, serial
        cid, serial = idaapi.get_next_serial_enum_member(cid, serial)


def iter_enum_constant_ids(eid):
    for bitmask in iter_bitmasks(eid):
        for value in iter_enum_member_values(eid, bitmask):
            for cid, serial in iter_serial_enum_member(eid, value, bitmask):
                yield cid


def iter_enum_ids():
    for index in xrange(idaapi.get_enum_qty()):
        yield idaapi.getn_enum(index)



def print_enum(name):
    # First, get the enum_id
    eid = idaapi.get_enum(name)

    for cid in iter_enum_constant_ids(eid):
        print idaapi.get_enum_member_name(cid)

def print_enums():
    for eid in iter_enum_ids():
        print_enum(idaapi.get_enum_name(eid))