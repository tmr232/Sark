import idaapi
import ida_typeinf
import idc
from . import exceptions
from contextlib import suppress

DEFMASK = -1

ENUM_ERROR_MAP = {
    ida_typeinf.TERR_BAD_NAME:
        (exceptions.SarkErrorEnumMemberName, "already have member with this name (bad name)"),
    ida_typeinf.TERR_BAD_VALUE:
        (exceptions.SarkErrorEnumMemberValue, "already have 256 members with this value"),
    ida_typeinf.TERR_BAD_TYPE:
        (exceptions.SarkErrorEnumMemberEnum, "bad typeid parameter"),
    ida_typeinf.TERR_BAD_BMASK:
        (exceptions.SarkErrorEnumMemberMask, "bad bmask"),
    ida_typeinf.TERR_BAD_MSKVAL:
        (exceptions.SarkErrorEnumMemberIllv, "bad bmask and value combination (~bmask & value != 0)"),
}


def _enum_member_error(err, tid, name, value, bitmask):
    """Format enum member error."""
    exception, msg = ENUM_ERROR_MAP[err]
    enum_name = idc.get_enum_name(tid)
    return exception(('add_enum_member(enum="{}", member="{}", value={}, bitmask=0x{:08X}) '
                      'failed: {}').format(
        enum_name,
        name,
        value,
        bitmask,
        msg
    ))


def _get_enum(name):
    """Get an existing enum type ID"""
    tid = idc.get_enum(name)
    if tid == idaapi.BADADDR:
        raise exceptions.EnumNotFound('Enum "{}" does not exist.'.format(name))
    return tid


def add_enum(name=None, index=None, flags=idaapi.hex_flag(), bitfield=False):
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
        with suppress(exceptions.EnumNotFound):
            _get_enum(name)
            raise exceptions.EnumAlreadyExists()

    # idx is not used anymore according to docs
    tid = idc.add_enum(0, name, flags)

    if tid == idaapi.BADADDR:
        raise exceptions.EnumCreationFailed('Failed creating enum "{}"'.format(name))

    if bitfield:
        idc.set_enum_bf(tid, bitfield)

    return Enum(tid=tid)


def remove_enum(name):
    """Delete an enum by name."""
    tid = _get_enum(name)
    idc.del_enum(tid)


def _add_enum_member(enum, name, value, bitmask=DEFMASK):
    """Add an enum member."""
    error = idc.add_enum_member(enum, name, value, bitmask)

    if error:
        raise _enum_member_error(error, enum, name, value, bitmask)


class EnumComments(object):
    """Enum comments retrieval and manipulation."""

    def __init__(self, tid):
        super(EnumComments, self).__init__()

        self._tid = tid

    @property
    def regular(self):
        return idc.get_enum_cmt(self._tid)

    @regular.setter
    def regular(self, comment):
        success = idc.set_enum_cmt(self._tid, comment, False)
        if not success:
            raise exceptions.CantSetEnumComment("Cant set enum comment.")

    @property
    def repeat(self):
        return idc.get_enum_cmt(self._tid)

    @repeat.setter
    def repeat(self, comment):
        success = idc.set_enum_cmt(self._tid, comment, True)
        if not success:
            raise exceptions.CantSetEnumComment("Cant set enum comment.")

    def __repr__(self):
        return ("EnumComments("
                "name={name!r},"
                " reqular={regular!r},"
                " repeat={repeat!r})").format(
            name=Enum(tid=self._tid).name,
            regular=self.regular,
            repeat=self.repeat, )


class EnumMembers(object):
    """Enum members retrieval and manipulation."""

    def __init__(self, tid):
        super(EnumMembers, self).__init__()
        self._tid = tid

    def __len__(self):
        """Number of members in the enum"""
        return idc.get_enum_size(self._tid)

    def __iter__(self):
        """Iterate all members of the enum"""
        return (EnumMember(cid) for cid in _iter_enum_constant_ids(self._tid))

    def add(self, name, value, bitmask=DEFMASK):
        """Add an enum member

        Args:
            name: Name of the member
            value: value of the member
            bitmask: bitmask. Only use if enum is a bitfield.
        """
        _add_enum_member(self._tid, name, value, bitmask)

    def __getitem__(self, name):
        """Get an enum member by name."""
        for enum_member in self:
            if enum_member.name == name:
                return enum_member
        raise KeyError("No member named {!r}".format(name))

    def remove(self, name):
        """Remove an enum member by name"""
        member = self[name]
        cid = member.cid
        value = member.value
        bmask = member.bmask

        success = idc.del_enum_member(self._tid, value, cid, bmask)
        if not success:
            raise exceptions.CantDeleteEnumMember("Can't delete enum member {!r}.".format(name))

    def __repr__(self):
        return "<EnumMembers(enum={!r}, members={{{}}})>".format(
            Enum(tid=self._tid).name,
            ", ".join("{member.name!r}: {member.value!r}".format(member=member) for member in self)
        )


class Enum(object):
    """An enum in the IDB"""

    def __init__(self, name=None, tid=None):
        """
        Get an existing enum.

        Only provide one of `name` and `tid`.

        Args:
            name: Name of the enum
            tid: Enum type ID
        """
        if None not in (name, tid):
            raise TypeError("Provide only a `name` or a `tid`.")

        self._tid = tid or _get_enum(name)
        self._comments = EnumComments(self._tid)

    @property
    def name(self):
        """Name of the enum"""
        return idc.get_enum_name(self.tid)

    @name.setter
    def name(self, name):
        """Set the enum name."""
        success = idc.set_enum_name(self.tid, name)
        if not success:
            raise exceptions.CantRenameEnum("Cant rename enum {!r} to {!r}.".format(self.name, name))

    @property
    def width(self):
        """Width of the enum"""
        return idc.get_enum_width(self.tid)

    @property
    def comments(self):
        """Enum comments"""
        return self._comments

    @property
    def tid(self):
        """Enum ID"""
        return self._tid

    @property
    def flag(self):
        """Enum flags (bitness, and display type)"""
        return idc.get_enum_flag(self.tid)

    @property
    def bitfield(self):
        """Is the enum a bitfield"""
        return idc.is_bf(self.tid)

    @bitfield.setter
    def bitfield(self, value):
        success = idc.set_enum_bf(self.tid, value)
        if not success:
            raise exceptions.CantSetEnumBitfield()

    @property
    def members(self):
        """Get the enum members."""
        return EnumMembers(self.tid)

    @property
    def is_from_til(self):
        """Is from type library?"""
        return ida_typeinf.get_tid_name(self.tid) is not None

    def __repr__(self):
        return "<Enum(name={!r})>".format(self.name)


class EnumMemberComments(object):
    """Enum member comments retrieval and manipulation."""

    def __init__(self, cid):
        super(EnumMemberComments, self).__init__()

        self._cid = cid

    @property
    def regular(self):
        return idc.get_enum_member_cmt(self._cid, False)

    @regular.setter
    def regular(self, comment):
        success = idc.set_enum_member_cmt(self._cid, comment, False)
        if not success:
            raise exceptions.CantSetEnumMemberComment("Cant set enum member comment.")

    @property
    def repeat(self):
        return idc.get_enum_member_cmt(self._cid, True)

    @repeat.setter
    def repeat(self, comment):
        success = idc.set_enum_member_cmt(self._cid, comment, True)
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
        return idc.get_enum_member_name(self.cid)

    @name.setter
    def name(self, name):
        """Set the member name.

        Note that a member name cannot appear in other enums, or generally
        anywhere else in the IDB.
        """
        success = idc.set_enum_member_name(self.cid, name)
        if not success:
            raise exceptions.CantRenameEnumMember(
                "Failed renaming {!r} to {!r}. Does the name exist somewhere else?".format(self.name, name))

    @property
    def bmask(self):
        """Get the bitmask"""
        return idc.get_enum_member_bmask(self.cid)

    bitmask = bmask

    @property
    def value(self):
        """Get the member value"""
        return idc.get_enum_member_value(self.cid)

    @property
    def comments(self):
        """Get the member comments"""
        return self._comments

    @property
    def parent(self):
        """Get the enum holding the member."""
        return Enum(tid=idc.get_enum_member_enum(self.cid))

    def __repr__(self):
        return "<EnumMember(name='{}.{}')>".format(self.parent.name, self.name)


def _iter_bitmasks(tid):
    """Iterate all bitmasks in a given enum.

    Note that while `DEFMASK` indicates no-more-bitmasks, it is also a
    valid bitmask value. The only way to tell if it exists is when iterating
    the serials.
    """
    bitmask = idc.get_first_bmask(tid)

    yield bitmask

    while bitmask != DEFMASK:
        bitmask = idc.get_next_bmask(tid, bitmask)
        yield bitmask


def _iter_enum_member_values(tid, bitmask):
    """Iterate member values with given bitmask inside the enum

    Note that `DEFMASK` can either indicate end-of-values or a valid value.
    Iterate serials to tell apart.
    """
    value = idc.get_first_enum_member(tid, bitmask)

    yield value
    while value != DEFMASK:
        value = idc.get_next_enum_member(tid, value, bitmask)
        yield value


def _iter_enum_member_cid_with_bitmask(tid, bitmask):
    """Iterate serial and CID of enum members with given value and bitmask.

    Here only valid values are returned, as `idaapi.BADNODE` always indicates
    an invalid member.
    """
    cid = idc.get_first_enum_member(tid, bmask=bitmask)
    while cid != DEFMASK:
        yield cid
        cid = idc.get_next_enum_member(tid, cid, bmask=bitmask)


def _iter_enum_constant_ids(tid):
    """Iterate the constant IDs of all members in the given enum"""
    for bitmask in _iter_bitmasks(tid):
        for cid in _iter_enum_member_cid_with_bitmask(tid, bitmask):
            yield cid


def _iter_types():
    """Iterate all types in the database"""
    til = ida_typeinf.get_idati()
    # get_ordinal_count returns 0 when numbered types
    # aren't enabled in the database (according to docs).
    if ida_typeinf.get_ordinal_count() == 0:
        for named in til.named_types():
            yield named
    else:
        for numbered in til.numbered_types():
            yield numbered


def _iter_enum_ids():
    """Iterate the IDs of all enums in the IDB"""
    for t in _iter_types():
        if t.is_enum():
            yield t.get_tid()


def enums():
    """Iterate all enums in the IDB"""
    return (Enum(tid=tid) for tid in _iter_enum_ids())
