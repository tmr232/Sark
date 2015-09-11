import idaapi
from . import exceptions
from awesome.context import ignored

DEFMASK = idaapi.BADADDR

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


def _enum_member_error(err, eid, name, value, bitmask):
    """Format enum member error."""
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


def _get_enum(name):
    """Get an existing enum ID"""
    eid = idaapi.get_enum(name)
    if eid == idaapi.BADADDR:
        raise exceptions.EnumNotFound('Enum "{}" does not exist.'.format(name))
    return eid


def add_enum(name=None, index=None, flags=idaapi.hexflag(), bitfield=False):
    """Create a new enum.

    Args:
        name: Name of the enum to create.
        index: The index of the enum. Leave at default to append the enum as the last enum.
        flags: Enum type flags.
        bitfield: Is the enum a bitfield.

    Returns:
        An `Enum` object.
    """
    if name is not None:
        with ignored(exceptions.EnumNotFound):
            _get_enum(name)
            raise exceptions.EnumAlreadyExists()

    if index is None or index < 0:
        index = idaapi.get_enum_qty()

    eid = idaapi.add_enum(index, name, flags)

    if eid == idaapi.BADADDR:
        raise exceptions.EnumCreationFailed('Failed creating enum "{}"'.format(name))

    if bitfield:
        idaapi.set_enum_bf(eid, bitfield)

    return Enum(eid=eid)

def remove_enum(name):
    """Delete an enum by name."""
    eid = _get_enum(name)
    idaapi.del_enum(eid)


def _add_enum_member(enum, name, value, bitmask=DEFMASK):
    """Add an enum member."""
    error = idaapi.add_enum_member(enum, name, value, bitmask)

    if error:
        raise _enum_member_error(error, enum, name, value, bitmask)


class EnumComments(object):
    """Enum comments retrieval and manipulation."""

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
    """Enum members retrieval and manipulation."""

    def __init__(self, eid):
        super(EnumMembers, self).__init__()
        self._eid = eid

    def __len__(self):
        """Number of members in the enum"""
        return idaapi.get_enum_size(self._eid)

    def __iter__(self):
        """Iterate all members of the enum"""
        return (EnumMember(cid) for cid in _iter_enum_constant_ids(self._eid))

    def add(self, name, value, bitmask=DEFMASK):
        """Add an enum member

        Args:
            name: Name of the member
            value: value of the member
            bitmask: bitmask. Only use if enum is a bitfield.
        """
        _add_enum_member(self._eid, name, value, bitmask)

    def __getitem__(self, name):
        """Get an enum member by name."""
        for enum_member in self:
            if enum_member.name == name:
                return enum_member
        raise KeyError("No member named {!r}".format(name))

    def remove(self, name):
        """Remove an enum member by name"""
        member = self[name]
        serial = member.serial
        value = member.value
        bmask = member.bmask

        success = idaapi.del_enum_member(self._eid, value, serial, bmask)
        if not success:
            raise exceptions.CantDeleteEnumMember("Can't delete enum member {!r}.".format(name))

    def __repr__(self):
        return "<EnumMembers(enum={!r}, members={{{}}})>".format(
            Enum(eid=self._eid).name,
            ", ".join("{member.name!r}: {member.value!r}".format(member=member) for member in self)
        )


class Enum(object):
    """An enum in the IDB"""

    def __init__(self, name=None, eid=None):
        """
        Get an existing enum.

        Only provide one of `name` and `eid`.

        Args:
            name: Name of the enum
            eid: Enum ID
        """
        if None not in (name, eid):
            raise TypeError("Provide only a `name` or an `eid`.")

        self._eid = eid or _get_enum(name)
        self._comments = EnumComments(self._eid)

    @property
    def name(self):
        """Name of the enum"""
        return idaapi.get_enum_name(self.eid)

    @name.setter
    def name(self, name):
        """Set the enum name."""
        success = idaapi.set_enum_name(self.eid, name)
        if not success:
            raise exceptions.CantRenameEnum("Cant rename enum {!r} to {!r}.".format(self.name, name))

    @property
    def width(self):
        """Width of the enum"""
        return idaapi.get_enum_width(self.eid)

    @property
    def comments(self):
        """Enum comments"""
        return self._comments

    @property
    def eid(self):
        """Enum ID"""
        return self._eid

    @property
    def flag(self):
        """Enum flags (bitness, and display type)"""
        return idaapi.get_enum_flag(self.eid)

    @property
    def bitfield(self):
        """Is the enum a bitfield"""
        return idaapi.is_bf(self.eid)

    @bitfield.setter
    def bitfield(self, value):
        success = idaapi.set_enum_bf(self.eid, value)
        if not success:
            raise exceptions.CantSetEnumBitfield()

    @property
    def members(self):
        """Get the enum members."""
        return EnumMembers(self.eid)

    @property
    def is_from_til(self):
        """Is from type library?"""
        return idaapi.is_enum_fromtil(self.eid)

    def __repr__(self):
        return "<Enum(name={!r})>".format(self.name)


class EnumMemberComments(object):
    """Enum member comments retrieval and manipulation."""

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
            name="{}.{}".format(enum_member.parent.name, enum_member.name),
            regular=self.regular,
            repeat=self.repeat, )


class EnumMember(object):
    """A member of an enum."""

    def __init__(self, cid):
        super(EnumMember, self).__init__()
        self._cid = cid
        self._comments = EnumMemberComments(self._cid)

    @property
    def cid(self):
        """Get the constant ID"""
        return self._cid

    @property
    def name(self):
        """Get the member name."""
        return idaapi.get_enum_member_name(self.cid)

    @name.setter
    def name(self, name):
        """Set the member name.

        Note that a member name cannot appear in other enums, or generally
        anywhere else in the IDB.
        """
        success = idaapi.set_enum_member_name(self.cid, name)
        if not success:
            raise exceptions.CantRenameEnumMember(
                "Failed renaming {!r} to {!r}. Does the name exist somewhere else?".format(self.name, name))

    @property
    def bmask(self):
        """Get the bitmask"""
        return idaapi.get_enum_member_bmask(self.cid)

    bitmask = bmask

    @property
    def value(self):
        """Get the member value"""
        return idaapi.get_enum_member_value(self.cid)

    @property
    def comments(self):
        """Get the member comments"""
        return self._comments

    @property
    def serial(self):
        """Get the member serial (among members of the same value)."""
        return idaapi.get_enum_member_serial(self.cid)

    @property
    def parent(self):
        """Get the enum holding the member."""
        return Enum(eid=idaapi.get_enum_member_enum(self.cid))

    def __repr__(self):
        return "<EnumMember(name='{}.{}')>".format(self.parent.name, self.name)


def _iter_bitmasks(eid):
    """Iterate all bitmasks in a given enum.

    Note that while `DEFMASK` indicates no-more-bitmasks, it is also a
    valid bitmask value. The only way to tell if it exists is when iterating
    the serials.
    """
    bitmask = idaapi.get_first_bmask(eid)

    yield bitmask

    while bitmask != DEFMASK:
        bitmask = idaapi.get_next_bmask(eid, bitmask)
        yield bitmask


def _iter_enum_member_values(eid, bitmask):
    """Iterate member values with given bitmask inside the enum

    Note that `DEFMASK` can either indicate end-of-values or a valid value.
    Iterate serials to tell apart.
    """
    value = idaapi.get_first_enum_member(eid, bitmask)

    yield value
    while value != DEFMASK:
        value = idaapi.get_next_enum_member(eid, value, bitmask)
        yield value


def _iter_serial_enum_member(eid, value, bitmask):
    """Iterate serial and CID of enum members with given value and bitmask.

    Here only valid values are returned, as `idaapi.BADNODE` always indicates
    an invalid member.
    """
    cid, serial = idaapi.get_first_serial_enum_member(eid, value, bitmask)
    while cid != idaapi.BADNODE:
        yield cid, serial
        cid, serial = idaapi.get_next_serial_enum_member(cid, serial)


def _iter_enum_constant_ids(eid):
    """Iterate the constant IDs of all members in the given enum"""
    for bitmask in _iter_bitmasks(eid):
        for value in _iter_enum_member_values(eid, bitmask):
            for cid, serial in _iter_serial_enum_member(eid, value, bitmask):
                yield cid


def _iter_enum_ids():
    """Iterate the IDs of all enums in the IDB"""
    for index in xrange(idaapi.get_enum_qty()):
        yield idaapi.getn_enum(index)


def enums():
    """Iterate all enums in the IDB"""
    return (Enum(eid=eid) for eid in _iter_enum_ids())
