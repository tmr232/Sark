import itertools
import idaapi
import idautils
import idc
from .base import is_ea_call
from ..core import fix_addresses
from .xref import Xref


class Comments(object):
    def __init__(self, ea):
        self._ea = ea

    @property
    def regular(self):
        return idc.Comment(self._ea)

    @regular.setter
    def regular(self, comment):
        idc.MakeComm(self._ea, comment)

    @property
    def repeat(self):
        return idc.RptCmt(self._ea)

    @repeat.setter
    def repeat(self, comment):
        idc.MakeRptCmt(self._ea, comment)

    @property
    def anterior(self):
        lines = (idc.LineA(self._ea, index) for index in itertools.count())
        return "\n".join(iter(lines.next, None))

    @anterior.setter
    def anterior(self, comment):
        index = 0

        for index, line in enumerate(comment.splitlines()):
            idc.ExtLinA(self._ea, index, line)

        idc.DelExtLnA(self._ea, index + 1)

    @property
    def posterior(self):
        lines = (idc.LineB(self._ea, index) for index in itertools.count())
        return "\n".join(iter(lines.next, None))

    @posterior.setter
    def posterior(self, comment):
        index = 0

        for index, line in enumerate(comment.splitlines()):
            idc.ExtLinB(self._ea, index, line)

        idc.DelExtLnB(self._ea, index + 1)


class Line(object):
    def __init__(self, ea):
        self._ea = idaapi.get_item_head(ea)
        self._comments = Comments(ea)

    @property
    def comments(self):
        return self._comments

    @property
    def ea(self):
        return self._ea

    @property
    def disasm(self):
        return idc.GetDisasm(self.ea)

    def __repr__(self):
        return "[{:08X}]    {}".format(self.ea, self.disasm)

    @property
    def xrefs_from(self):
        return map(Xref, idautils.XrefsFrom(self.ea))

    @property
    def drefs_from(self):
        return idautils.DataRefsFrom(self.ea)

    @property
    def crefs_from(self):
        return idautils.CodeRefsFrom(self.ea, 1)

    @property
    def xrefs_to(self):
        return map(Xref, idautils.XrefsTo(self.ea))

    @property
    def drefs_to(self):
        return idautils.DataRefsTo(self.ea)

    @property
    def crefs_to(self):
        return idautils.CodeRefsTo(self.ea, 1)

    @property
    def size(self):
        return idaapi.get_item_size(self.ea)

    @property
    def is_call(self):
        return is_ea_call(self.ea)

    @property
    def name(self):
        return idc.Name(self.ea)

    @name.setter
    def name(self, value):
        idc.MakeName(self.ea, value)

    @property
    def inst(self):
        return idautils.DecodeInstruction(self.ea)

    @property
    def color(self):
        return idc.GetColor(self.ea, idc.CIC_ITEM)

    @color.setter
    def color(self, color):
        if color is None:
            color = 0xFFFFFFFF

        idc.SetColor(self.ea, idc.CIC_ITEM, color)


def iter_lines(start=None, end=None):
    start, end = fix_addresses(start, end)

    item = idaapi.get_item_head(start)
    while item < end:
        yield Line(item)
        item += idaapi.get_item_size(item)