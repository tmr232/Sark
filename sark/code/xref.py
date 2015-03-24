import idaapi
import idc


class XrefType(object):
    """Xref Type Wrapper.

    Provides easy to use parsing of xref types.
    All the properties are flag checks on the type value.
    """
    TYPES = {
        0x00: 'Data_Unknown',
        0x01: 'Data_Offset',
        0x02: 'Data_Write',
        0x03: 'Data_Read',
        0x04: 'Data_Text',
        0x05: 'Data_Informational',
        0x10: 'Code_Far_Call',
        0x11: 'Code_Near_Call',
        0x12: 'Code_Far_Jump',
        0x13: 'Code_Near_Jump',
        0x14: 'Code_User',
        0x15: 'Ordinary_Flow'
    }

    def __init__(self, type_):
        self._type = type_

    @property
    def type(self):
        """Raw `type` value

        Use this if you need to pass the xref type around as a number.
        """
        return self._type

    @property
    def name(self):
        """Name of the xref type."""
        return self.TYPES[self._type]

    def __repr__(self):
        return self.name

    @property
    def is_code(self):
        return self._type & 0x10

    @property
    def is_data(self):
        return not self.is_code

    @property
    def is_unknown(self):
        return self._type == idaapi.fl_U

    @property
    def is_offset(self):
        return self._type == idaapi.dr_O

    @property
    def is_write(self):
        return self._type == idaapi.dr_W

    @property
    def is_read(self):
        return self._type == idaapi.dr_R

    @property
    def is_text(self):
        return self._type == idaapi.dr_T

    @property
    def is_info(self):
        return self._type == idaapi.dr_I

    @property
    def is_far_call(self):
        return self._type == idaapi.fl_CF

    @property
    def is_near_call(self):
        return self._type == idaapi.fl_CN

    @property
    def is_far_jump(self):
        return self._type == idaapi.fl_JF

    @property
    def is_near_jump(self):
        return self._type == idaapi.fl_JN

    @property
    def is_user(self):
        return self._type == idaapi.fl_U

    @property
    def is_flow(self):
        return self._type == idaapi.fl_F

    @property
    def is_call(self):
        return self.is_far_call or self.is_near_call

    @property
    def is_jump(self):
        return self.is_far_jump or self.is_near_jump


class Xref(object):
    """Xref Object

    Provides easy access to xref attributes.
    Most interesting data (xref type) is accessible via the `.type`
    attribute.
    """
    def __init__(self, xref):
        for attr in [ 'frm', 'to', 'iscode', 'user' ]:
            setattr(self, attr, getattr(xref, attr))

        self._type = XrefType(xref.type)

    @property
    def type(self):
        return self._type

    def __repr__(self):
        frm = idc.Name(self.frm)
        if frm:
            frm = repr(frm)
        else:
            frm = "0x{:08X}".format(self.frm)

        to = idc.Name(self.to)
        if frm:
            to = repr(to)
        else:
            to = "0x{:08X}".format(self.to)

        return "<Xref(frm={frm}, to={to}, iscode={iscode}, user={user}, type={type})>".format(
            frm=frm,
            to=to,
            iscode=self.iscode,
            user=self.user,
            type=self.type,
        )