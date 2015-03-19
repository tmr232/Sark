import itertools
import idaapi
import idautils
import idc
from .base import is_ea_call
from ..core import fix_addresses
from .xref import Xref
from .instruction import Instruction
from ..ui import updates_ui


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
    @updates_ui
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
    @updates_ui
    def posterior(self, comment):
        index = 0

        for index, line in enumerate(comment.splitlines()):
            idc.ExtLinB(self._ea, index, line)

        idc.DelExtLnB(self._ea, index + 1)

    def __repr__(self):
        return ("Comments("
                "ea=0x{ea:08X},"
                " reqular={regular},"
                " repeat={repeat},"
                " anterior={anterior},"
                " posterior={posterior})").format(
            ea=self._ea,
            regular=repr(self.regular),
            repeat=repr(self.repeat),
            anterior=repr(self.anterior),
            posterior=repr(self.posterior))


class Line(object):
    def __init__(self, ea=None):
        """An IDA Line.

        This objects encapsulates many of IDA's line-handling APIs in an easy to use
        and object oriented way.

        :param ea: Line address. Uses current GUI position if `None`.
        """
        if ea is None:
            ea = idc.here()

        self._ea = idaapi.get_item_head(ea)
        self._comments = Comments(ea)

    @property
    def comments(self):
        """Comments"""
        return self._comments

    @property
    def ea(self):
        """Line EA"""
        return self._ea

    @property
    def disasm(self):
        """Line Disassembly"""
        return idc.GetDisasm(self.ea)

    def __repr__(self):
        return "[{:08X}]    {}".format(self.ea, self.disasm)

    @property
    def xrefs_from(self):
        """Xrefs from this line.

        :return: Xrefs as `sark.code.xref.Xref` objects.
        """
        return map(Xref, idautils.XrefsFrom(self.ea))

    @property
    def drefs_from(self):
        """Destination addresses of data references from this line."""
        return idautils.DataRefsFrom(self.ea)

    @property
    def crefs_from(self):
        """Destination addresses of code references from this line."""
        return idautils.CodeRefsFrom(self.ea, 1)

    @property
    def xrefs_to(self):
        """Xrefs to this line.

        :return: Xrefs as `sark.code.xref.Xref` objects.
        """
        return map(Xref, idautils.XrefsTo(self.ea))

    @property
    def drefs_to(self):
        """Source addresses of data references from this line."""
        return idautils.DataRefsTo(self.ea)

    @property
    def crefs_to(self):
        """Source addresses of data references to this line."""
        return idautils.CodeRefsTo(self.ea, 1)

    @property
    def size(self):
        """Size (in bytes) of the line."""
        return idaapi.get_item_size(self.ea)

    @property
    def is_call(self):
        return is_ea_call(self.ea)

    @property
    def name(self):
        """Name of the line (the label shown in IDA)."""
        return idc.Name(self.ea)

    @name.setter
    def name(self, value):
        idc.MakeName(self.ea, value)

    @property
    def insn(self):
        return Instruction(self.ea)

    @property
    def color(self):
        return idc.GetColor(self.ea, idc.CIC_ITEM)

    @color.setter
    def color(self, color):
        if color is None:
            color = 0xFFFFFFFF

        idc.SetColor(self.ea, idc.CIC_ITEM, color)


def lines(start=None, end=None):
    """Iterate lines in range.

    :param start: Starting address, start of IDB if `None`.
    :param end: End address, end of IDB if `None`.
    :return: iterator of `Line` objects.
    """
    start, end = fix_addresses(start, end)

    item = idaapi.get_item_head(start)
    while item < end:
        yield Line(item)
        item += idaapi.get_item_size(item)