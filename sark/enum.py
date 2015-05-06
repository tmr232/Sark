import idaapi
from . import exceptions
from awesome.context import ignored

DEFMASK = 0xFFFFFFFF

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


def enum_member_error(err, eid, name, value, bitmask):
    exception, msg = ENUM_ERROR_MAP[err]
    enum_name = idaapi.get_enum_name(eid)
    return exception(('add_enum_member(enum="{}", member="{}", value={}, bitmask=0x{:08X}) '
                      'failed: {}').format(
        enum_name,
        name,
        value,
        bitmask,
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

    eid = idaapi.add_enum(index, name, flags)

    if eid == idaapi.BADADDR:
        raise exceptions.EnumCreationFailed('Failed creating enum "{}"'.format(name))

    if bitfield:
        idaapi.set_enum_bf(eid, bitfield)

    return Enum(eid)


def add_enum_member(enum, name, value, bitmask=DEFMASK):
    error = idaapi.add_enum_member(enum, name, value, bitmask)

    if error:
        raise enum_member_error(error, enum, name, value, bitmask)


class EnumComments(object):
    def __init__(self, eid):
        super(EnumComments, self).__init__()

        self._eid = eid

    @property
    def regular(self):
        return idaapi.get_enum_cmt(self._eid, False)

    @regular.setter
    def regular(self, comment):
        success = idaapi.set_enum_cmt(self._eid, comment, False)
        if not success:
            raise exceptions.CantSetEnumComment("Cant set enum comment.")


    @property
    def repeat(self):
        return idaapi.get_enum_cmt(self._eid, True)

    @repeat.setter
    def repeat(self, comment):
        success = idaapi.set_enum_cmt(self._eid, comment, True)
        if not success:
            raise exceptions.CantSetEnumComment("Cant set enum comment.")

    def __repr__(self):
        return ("EnumComments("
                "name={name!r},"
                " reqular={regular!r},"
                " repeat={repeat!r})").format(
            name=Enum(eid=self._eid).name,
            regular=self.regular,
            repeat=self.repeat, )


class EnumMembers(object):
    def __init__(self, eid):
        super(EnumMembers, self).__init__()
        self._eid = eid

    def __len__(self):
        return idaapi.get_enum_size(self._eid)

    def __iter__(self):
        return (EnumMember(cid) for cid in iter_enum_constant_ids(self._eid))

    def add(self, name, value, bitmask=DEFMASK):
        add_enum_member(self._eid, name, value, bitmask)

    def __getitem__(self, name):
        for enum_member in self:
            if enum_member.name == name:
                return enum_member
        raise KeyError("No member named {!r}".format(name))

    def remove(self, name):
        member = self[name]
        serial = member.serial
        value = member.value
        bmask = member.bmask

        success = idaapi.del_enum_member(self._eid, value, serial, bmask)
        if not success:
            raise exceptions.CantDeleteEnumMember("Can't delete enum member {!r}.".format(name))


class Enum(object):
    def __init__(self, name=None, eid=None):
        if None not in (name, eid):
            raise TypeError("Provide only a `name` or an `eid`.")
        self._eid = eid or get_enum(name)
        self._comments = EnumComments(self._eid)

    @property
    def name(self):
        return idaapi.get_enum_name(self.eid)

    @property
    def width(self):
        return idaapi.get_enum_width(self.eid)

    @property
    def comments(self):
        return self._comments

    @property
    def eid(self):
        return self._eid

    @property
    def flag(self):
        return idaapi.get_enum_flag(self.eid)

    @property
    def bitfield(self):
        return idaapi.is_bf(self.eid)

    @bitfield.setter
    def bitfield(self, value):
        success = idaapi.set_enum_bf(self.eid, value)
        if not success:
            raise exceptions.CantSetEnumBitfield()

    @property
    def members(self):
        return EnumMembers(self.eid)

    def __repr__(self):
        return "<Enum(name={!r})>".format(self.name)


class EnumMemberComments(object):
    def __init__(self, cid):
        super(EnumMemberComments, self).__init__()

        self._cid = cid

    @property
    def regular(self):
        return idaapi.get_enum_member_cmt(self._cid, False)

    @regular.setter
    def regular(self, comment):
        success = idaapi.set_enum_member_cmt(self._cid, comment, False)
        if not success:
            raise exceptions.CantSetEnumMemberComment("Cant set enum member comment.")


    @property
    def repeat(self):
        return idaapi.get_enum_member_cmt(self._cid, True)

    @repeat.setter
    def repeat(self, comment):
        success = idaapi.set_enum_member_cmt(self._cid, comment, True)
        if not success:
            raise exceptions.CantSetEnumMemberComment("Cant set enum member comment.")

    def __repr__(self):
        enum_member = EnumMember(self._cid)
        return ("EnumMemberComments("
                "name={name!r},"
                " reqular={regular!r},"
                " repeat={repeat!r})").format(
            name="{}.{}".format(enum_member.enum.name, enum_member.name),
            regular=self.regular,
            repeat=self.repeat, )


class EnumMember(object):
    def __init__(self, cid):
        super(EnumMember, self).__init__()
        self._cid = cid
        self._comments = EnumMemberComments(self._cid)

    @property
    def cid(self):
        return self._cid

    @property
    def name(self):
        return idaapi.get_enum_member_name(self.cid)

    @name.setter
    def name(self, name):
        success = idaapi.set_enum_member_name(self.cid, name)
        if not success:
            raise exceptions.CantRenameEnumMember(
                "Failed renaming {!r} to {!r}. Does the name exist somewhere else?".format(self.name, name))

    @property
    def bmask(self):
        return idaapi.get_enum_member_bmask(self.cid)

    bitmask = bmask

    @property
    def value(self):
        return idaapi.get_enum_member_value(self.cid)

    @property
    def comments(self):
        return self._comments

    @property
    def serial(self):
        return idaapi.get_enum_member_serial(self.cid)

    @property
    def enum(self):
        return Enum(eid=idaapi.get_enum_member_enum(self.cid))

    def __repr__(self):
        return "<EnumMember(name='{}.{}')>".format(self.enum.name, self.name)


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