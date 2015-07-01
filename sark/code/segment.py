import idc
import idaapi
import idautils
from .function import functions
from .line import lines


class Comments(object):
    def __init__(self, segment):
        self._segment = segment

    @property
    def regular(self):
        return idaapi.get_segment_cmt(self._segment, False)

    @regular.setter
    def regular(self, comment):
        idaapi.set_segment_cmt(self._segment, comment, False)

    @property
    def repeat(self):
        return idaapi.get_segment_cmt(self._segment, True)

    @repeat.setter
    def repeat(self, comment):
        idaapi.set_segment_cmt(self._segment, comment, True)


class SegmentPermissions(object):
    def __init__(self, segment_t):
        self._segment = segment_t

    @property
    def x(self):
        return self._segment.perm & idaapi.SEGPERM_EXEC

    @x.setter
    def x(self, value):
        if value:
            self._segment.perm |= idaapi.SEGPERM_EXEC

        else:
            self._segment.perm &= ~idaapi.SEGPERM_EXEC

    @property
    def w(self):
        return self._segment.perm & idaapi.SEGPERM_WRITE

    @w.setter
    def w(self, value):
        if value:
            self._segment.perm |= idaapi.SEGPERM_WRITE

        else:
            self._segment.perm &= ~idaapi.SEGPERM_WRITE

    @property
    def r(self):
        return self._segment.perm & idaapi.SEGPERM_READ

    @r.setter
    def r(self, value):
        if value:
            self._segment.perm |= idaapi.SEGPERM_READ

        else:
            self._segment.perm &= ~idaapi.SEGPERM_READ

    execute = x
    write = w
    read = r

    def __str__(self):
        return "".join(("R" if self.r else "", "W" if self.w else "", "X" if self.x else ""))

    def __repr__(self):
        return "<SegmentPermissions(read={}, write={}, execute={})>".format(bool(self.r), bool(self.w), bool(self.x))


class Segment(object):
    class UseCurrentAddress(object):
        pass

    def __init__(self, ea=UseCurrentAddress, name=None, index=None):
        """Wrapper around IDA segments.

        There are 3 ways to get a segment - by name, ea or index. Only use one.

        Args:
            ea - address in the segment
            name - name of the segment
            index - index of the segment
        """
        if sum((ea not in (self.UseCurrentAddress, None), name is not None, index is not None,)) > 1:
            raise ValueError(
                "Expected only one (ea, name or index). Got (ea={!r}, name={!r}, index={!r})".format(ea, name, index))

        elif name is not None:
            seg = idaapi.get_segm_by_name(name)

        elif index is not None:
            seg = idaapi.getnseg(index)

        elif ea == self.UseCurrentAddress:
            seg = idaapi.getseg(idc.here())

        elif ea is None:
            raise ValueError("`None` is not a valid address. To use the current screen ea, "
                             "use `Function(ea=Function.UseCurrentAddress)` or supply no `ea`.")

        else:
            seg = idaapi.getseg(ea)

        self._segment = seg

    @property
    def segment_t(self):
        return self._segment

    @property
    def permissions(self):
        """Segment permissions.

        Can be used to get or set the segment permissions (r/w/x).

        Returns:
            A `SegmentPermissions` object.
        """
        return SegmentPermissions(self.segment_t)

    @property
    def startEA(self):
        return self._segment.startEA

    ea = startEA

    @property
    def endEA(self):
        return self._segment.endEA

    @property
    def name(self):
        return idaapi.get_segm_name(self.segment_t)

    @name.setter
    def name(self, name):
        idaapi.set_segm_name(self.segment_t, name)

    @property
    def class_(self):
        return idaapi.get_segm_class(self.segment_t)

    @class_.setter
    def class_(self, value):
        idaapi.set_segm_class(self.segment_t, value)

    @property
    def functions(self):
        """Iterate all functions in the segment."""
        return functions(self.startEA, self.endEA)

    @property
    def lines(self):
        """Iterate all lines in the segment."""
        return lines(self.startEA, self.endEA)

    @property
    def next(self):
        """Get the next segment."""
        return Segment(idaapi.get_next_seg(self.ea))

    @property
    def prev(self):
        """Get the previous segment."""
        return Segment(idaapi.get_prev_seg(self.ea))

    @property
    def comments(self):
        return Comments(self.segment_t)

    @property
    def size(self):
        return self.endEA - self.startEA

    def __repr__(self):
        return "<Segment(ea=0x{:08X}, name={!r}, size=0x{:08X}, permissions={!r})>".format(self.ea,
                                                                                           self.name,
                                                                                           self.size,
                                                                                           str(self.permissions))


def segments():
    for index in xrange(idaapi.get_segm_qty()):
        yield Segment(index=index)
