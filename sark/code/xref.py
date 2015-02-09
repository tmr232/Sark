import idaapi


class XrefType(object):
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
    def name(self):
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
    def __init__(self, xref):
        for attr in [ 'frm', 'to', 'iscode', 'user' ]:
            setattr(self, attr, getattr(xref, attr))

        self._type = XrefType(xref.type)

    @property
    def type(self):
        return self._type