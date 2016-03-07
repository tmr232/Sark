from itertools import imap, count
import idaapi
import idautils
import idc
from ..core import fix_addresses
from .xref import Xref
from .instruction import Instruction
from ..ui import updates_ui
from .base import get_selection


class Comments(object):
    """IDA Line Comments

    Provides easy access to all types of comments for an IDA line.
    """

    def __init__(self, ea):
        self._ea = ea

    def __nonzero__(self):
        return any((self.regular, self.repeat, self.anterior, self.posterior,))

    @property
    def regular(self):
        """Regular Comment"""
        return idc.Comment(self._ea)

    @regular.setter
    def regular(self, comment):
        idc.MakeComm(self._ea, comment)

    @property
    def repeat(self):
        """Repeatable Comment"""
        return idc.RptCmt(self._ea)

    @repeat.setter
    def repeat(self, comment):
        idc.MakeRptCmt(self._ea, comment)

    @property
    def anterior(self):
        """Anterior Comment"""
        lines = (idc.LineA(self._ea, index) for index in count())
        return "\n".join(iter(lines.next, None))

    @anterior.setter
    @updates_ui
    def anterior(self, comment):
        if not comment:
            idc.DelExtLnA(self._ea, 0)
            return
        
        index = 0

        for index, line in enumerate(comment.splitlines()):
            idc.ExtLinA(self._ea, index, line)

        idc.DelExtLnA(self._ea, index + 1)

    @property
    def posterior(self):
        """Posterior Comment"""
        lines = (idc.LineB(self._ea, index) for index in count())
        return "\n".join(iter(lines.next, None))

    @posterior.setter
    @updates_ui
    def posterior(self, comment):
        if not comment:
            idc.DelExtLnB(self._ea, 0)
            return
        
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
    """
    An IDA Line.

    This objects encapsulates many of IDA's line-handling APIs in an easy to use
    and object oriented way.
    """

    class UseCurrentAddress(object):
        """
        This is a filler object to replace `None` for the EA.
        In many cases, a programmer can accidentally initialize the
        `Line` object with `ea=None`, resulting in the current address.
        Usually, this is not the desired outcome. This object resolves this issue.
        """
        pass


    def __init__(self, ea=UseCurrentAddress, name=None):
        if name is not None and ea != self.UseCurrentAddress:
            raise ValueError(("Either supply a name or an address (ea). "
                              "Not both. (ea={!r}, name={!r})").format(ea, name))

        elif name is not None:
            ea = idc.LocByName(name)

        elif ea == self.UseCurrentAddress:
            ea = idc.here()

        elif ea is None:
            raise ValueError("`None` is not a valid address. To use the current screen ea, "
                             "use `Line(ea=Line.UseCurrentAddress)` or supply no `ea`.")

        self._ea = idaapi.get_item_head(ea)
        self._comments = Comments(ea)

    @property
    def flags(self):
        """`FF_*` Flags. See `bytes.hpp`."""
        return idaapi.getFlags(self.ea)

    @property
    def is_code(self):
        """Is the line code."""
        return idaapi.isCode(self.flags)

    @property
    def is_data(self):
        """Is the line data."""
        return idaapi.isData(self.flags)

    @property
    def is_unknown(self):
        """Is the line unknown."""
        return idaapi.isUnknown(self.flags)

    @property
    def is_tail(self):
        """Is the line a tail."""
        return idaapi.isTail(self.flags)

    @property
    def comments(self):
        """Comments"""
        return self._comments

    @property
    def ea(self):
        """Line EA"""
        return self._ea

    startEA = ea

    @property
    def endEA(self):
        """End address of line (first byte after the line)"""
        return self.ea + self.size

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
        return imap(Xref, idautils.XrefsFrom(self.ea))

    @property
    def has_xrefs_from(self):
        """Are there Xrefs from this line."""
        return len(list(self.xrefs_from)) != 0

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

        Returns:
            Xrefs as `sark.code.xref.Xref` objects.
        """
        return imap(Xref, idautils.XrefsTo(self.ea))

    @property
    def has_xrefs_to(self):
        """Are there Xrefs to this line."""
        return len(list(self.xrefs_to)) != 0

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
    def name(self):
        """Name of the line (the label shown in IDA)."""
        return idc.GetTrueName(self.ea)

    @name.setter
    def name(self, value):
        idc.MakeName(self.ea, value)

    @property
    def insn(self):
        """Instruction"""
        return Instruction(self.ea)

    @property
    def color(self):
        """Line color in IDA View"""
        color = idc.GetColor(self.ea, idc.CIC_ITEM)
        if color == 0xFFFFFFFF:
            return None

        return color

    @color.setter
    @updates_ui
    def color(self, color):
        """Line Color in IDA View.

        Set color to `None` to clear the color.
        """
        if color is None:
            color = 0xFFFFFFFF

        idc.SetColor(self.ea, idc.CIC_ITEM, color)

    @property
    def next(self):
        """The next line."""
        return Line(self.endEA)

    @property
    def prev(self):
        """The previous line."""
        return Line(self.ea - 1)

    @property
    def has_name(self):
        """Does the current line have a non-trivial (non-dummy) name?"""
        return idaapi.has_name(self.flags)


def lines(start=None, end=None, reverse=False, selection=False):
    """Iterate lines in range.

    Args:
        start: Starting address, start of IDB if `None`.
        end: End address, end of IDB if `None`.
        reverse: Set to true to iterate in reverse order.
        selection: If set to True, replaces start and end with current selection.

    Returns:
        iterator of `Line` objects.
    """
    if selection:
        start, end = get_selection()

    else:
        start, end = fix_addresses(start, end)

    if not reverse:
        item = idaapi.get_item_head(start)
        while item < end:
            yield Line(item)
            item += idaapi.get_item_size(item)

    else:  # if reverse:
        item = idaapi.get_item_head(end - 1)
        while item >= start:
            yield Line(item)
            item = idaapi.get_item_head(item - 1)