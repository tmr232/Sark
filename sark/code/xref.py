import idaapi
import idautils
import idc
from ..core import get_name_or_address


class XrefCreationError(Exception):
    pass


class XrefTypes(object):
    """Xref Types"""

    class XrefType(object):
        """Wrapper for an xref value"""

        def __init__(self, value):
            self._value = value

        @property
        def value(self):
            return self._value

        def __str__(self):
            return self.__repr__()

        def __repr__(self):
            return idautils.XrefTypeName(self.value)

        @property
        def is_code(self):
            return (self._value & 0x10) == 0x10

        @property
        def is_data(self):
            return not self.is_code

    UnknownData = XrefType(idaapi.dr_U)
    OffsetData = XrefType(idaapi.dr_O)
    WriteData = XrefType(idaapi.dr_W)
    ReadData = XrefType(idaapi.dr_R)
    TextData = XrefType(idaapi.dr_T)
    InfoData = XrefType(idaapi.dr_I)
    FarCall = XrefType(idaapi.fl_CF)
    NearCall = XrefType(idaapi.fl_CN)
    FarJump = XrefType(idaapi.fl_JF)
    NearJump = XrefType(idaapi.fl_JN)
    UserSpecifiedCode = XrefType(idaapi.fl_USobsolete)  # obsolete
    OrdinaryFlow = XrefType(idaapi.fl_F)


def add_xref(frm, to, xref_type):
    """
    Add an xref
    :param frm: source address
    :param to: target address
    :param xref_type: see sark.xref.XrefTypes
    :return: whether the xref was added successfully
    """

    if xref_type.is_code:
        result = idaapi.add_cref(frm, to, xref_type.value | idaapi.XREF_USER)
    else:
        result = idaapi.add_dref(frm, to, xref_type.value | idaapi.XREF_USER)

    if not result:
        raise XrefCreationError("Failed creating xref, {} from {} to {}".format(frm, to, xref_type))

    return Xref(frm, to, xref_type, True)


class Xref(object):
    """Xref Object

    Provides easy access to xref attributes.
    Most interesting data (xref type) is accessible via the `.type`
    attribute.
    """

    def __init__(self, frm, to, xref_type, is_user_xref):
        self._frm = frm
        self._to = to
        self._type = xref_type
        self._user = is_user_xref

    @property
    def type(self):
        return self._type

    @property
    def frm(self):
        return self.frm

    @property
    def to(self):
        return self._to

    @property
    def is_user_xref(self):
        return self._user

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "<Xref(frm={frm}, to={to}, type={type}, user_xref={user})>".format(
            frm=get_name_or_address(self._frm),
            to=get_name_or_address(self._to),
            user=self._user,
            type=repr(self.type),
        )


def remove_xref(frm, to, xref_type):
    """
    Removes an xref
    :param frm: source address of xref
    :param to: target address of xref
    :param xref_type: type of xref between addresses
    """
    if xref_type.is_code:
        idaapi.del_cref(frm, to, 0)
    else:
        idaapi.del_dref(frm, to)
