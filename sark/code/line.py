from itertools import imap
import idaapi
import idautils
import idc
from ..core import fix_addresses
from .xref import Xref
from .instruction import Instruction
from ..ui import updates_ui
from .base import get_selection, get_offset_name, demangle
from .. import data


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

    def _iter_extra_comments(self, start):
        end = idaapi.get_first_free_extra_cmtidx(self._ea, start)
        for idx in xrange(start, end):
            line = idaapi.get_extra_cmt(self._ea, idx)
            yield line or ''

    def _iter_anterior(self):
        return self._iter_extra_comments(idaapi.E_PREV)

    @property
    def anterior(self):
        """Anterior Comment"""
        return "\n".join(self._iter_anterior())

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

    def _iter_posterior(self):
        return self._iter_extra_comments(idaapi.E_NEXT)

    @property
    def posterior(self):
        """Posterior Comment"""
        return "\n".join(self._iter_posterior())

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


class Xrefs(object):
    """
    IDA Line Xrefs

    Provides easy access to all types of xrefs for an IDA line.
    """

    class _DirectedXrefs(object):

        def __init__(self, ea, to):
            self._ea = ea
            self._to = to

        def __iter__(self):
            """Xrefs from/to this line.

            :return: Xrefs as `sark.code.xref.Xref` objects.
            """
            for x in imap(Xref, idautils.XrefsTo(self._ea) if self._to else idautils.XrefsFrom(self._ea)):
                yield x

        @property
        def calls(self):
            return (xref for xref in self if xref.type.is_call)

        @property
        def drefs(self):
            """Addresses of data references from/to this line."""
            return idautils.DataRefsTo(self._ea) if self._to else idautils.DataRefsFrom(self._ea)

        def dref_add(self, line):
            """Add data reference from/to this line to line."""
            if self._to:
                return idaapi.add_dref(line.ea, self._ea, idaapi.dr_I | idaapi.XREF_USER)
            else:
                return idaapi.add_dref(self._ea, line.ea, idaapi.dr_I | idaapi.XREF_USER)

        def dref_remove(self, line):
            """Remove data reference from/to this line to to_line."""
            if self._to:
                idaapi.del_dref(line.ea, self._ea)
            else:
                idaapi.del_dref(self._ea, line.ea)
            # del_dref has meaningless return value

        @property
        def crefs(self):
            """Addresses of code references from/to this line."""
            return idautils.CodeRefsTo(self._ea, 1) if self._to else idautils.CodeRefsFrom(self._ea, 1)

        def cref_add(self, line):
            """Add code reference from/to this line to line."""
            if self._to:
                return idaapi.add_cref(line.ea, self._ea, idaapi.dr_I | idaapi.XREF_USER)
            else:
                return idaapi.add_cref(self._ea, line.ea, idaapi.dr_I | idaapi.XREF_USER)

        def cref_remove(self, line):
            """Remove code reference from/to this line to to_line."""
            AVOID_DEL_DST = 0  # avoid deletion of destination if no more crefs to
            if self._to:
                idaapi.del_cref(line.ea, self._ea, AVOID_DEL_DST)
            else:
                idaapi.del_cref(self._ea, line.ea, AVOID_DEL_DST)
            # del_cref has meaningless return value

    def __init__(self, ea):
        self._ea = ea
        self._to = Xrefs._DirectedXrefs(ea, to=True)
        self._frm = Xrefs._DirectedXrefs(ea, to=False)

    @property
    def to(self):
        """Xrefs to this line"""
        return self._to

    @property
    def frm(self):
        """Xrefs from this line"""
        return self._frm


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
        self._xrefs = Xrefs(ea)

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
    def is_string(self):
        """Is the line a string."""
        return data.is_string(self.ea)

    @property
    def comments(self):
        """Comments"""
        return self._comments

    @property
    def xrefs(self):
        """Xrefs"""
        return self._xrefs

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

    @property
    def type(self):
        """return the type of the Line """
        properties = {self.is_code: "code",
                      self.is_data: "data",
                      self.is_string: "string",
                      self.is_tail: "tail",
                      self.is_unknown: "unknown"}
        for k, v in properties.items():
            if k: return v

    def __repr__(self):
        return "[{:08X}]    {}".format(self.ea, self.disasm)

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
    def demangled(self):
        """Return the demangled name of the line. If none exists, return `.name`"""
        return demangle(self.name)

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

    @property
    def offset_name(self):
        return get_offset_name(self.ea)

    @property
    def bytes(self):
        return idaapi.get_many_bytes(self.ea, self.size)

    def __eq__(self, other):
        if not isinstance(other, Line):
            return False

        return self.ea == other.ea

    def __ne__(self, other):
        return not self.__eq__(other)


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
