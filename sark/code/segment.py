import idc
import idaapi
import idautils
from .function import functions
from .line import lines
from .. import exceptions

class Comments(object):
    def __init__(self, segment):
        super(Comments, self).__init__()
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
        super(SegmentPermissions, self).__init__()
        self._segment = segment_t

    @property
    def x(self):
        return bool(self._segment.perm & idaapi.SEGPERM_EXEC)

    @x.setter
    def x(self, value):
        if value:
            self._segment.perm |= idaapi.SEGPERM_EXEC

        else:
            self._segment.perm &= ~idaapi.SEGPERM_EXEC

    @property
    def w(self):
        return bool(self._segment.perm & idaapi.SEGPERM_WRITE)

    @w.setter
    def w(self, value):
        if value:
            self._segment.perm |= idaapi.SEGPERM_WRITE

        else:
            self._segment.perm &= ~idaapi.SEGPERM_WRITE

    @property
    def r(self):
        return bool(self._segment.perm & idaapi.SEGPERM_READ)

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
        return "<SegmentPermissions(read={}, write={}, execute={})>".format(self.r, self.w, self.x)


class Segment(object):
    BITNESS_TO_BITS = {
        0: 16,
        1: 32,
        2: 64,
    }

    BITS_TO_BITNESS = {
        16: 0,
        32: 1,
        64: 2,
    }

    class UseCurrentAddress(object):
        pass

    def __init__(self, ea=UseCurrentAddress, name=None, index=None, segment_t=None):
        """Wrapper around IDA segments.

        There are 3 ways to get a segment - by name, ea or index. Only use one.

        Args:
            ea - address in the segment
            name - name of the segment
            index - index of the segment
        """
        if sum((ea not in (self.UseCurrentAddress, None), name is not None, index is not None,
                segment_t is not None,)) > 1:
            raise ValueError((
                                 "Expected only one (ea, name, index or segment_t)."
                                 " Got (ea={!r}, name={!r}, index={!r}, segment_t={!r})"
                             ).format(ea,
                                      name,
                                      index,
                                      segment_t))


        elif segment_t is not None:
            seg = segment_t

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
    def start_ea(self):
        return self._segment.start_ea

    ea = start_ea

    @property
    def end_ea(self):
        return self._segment.end_ea

    @property
    def type(self):
        return idaapi.segtype(self.ea)

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
        return functions(self.start_ea, self.end_ea)

    @property
    def lines(self):
        """Iterate all lines in the segment."""
        return lines(self.start_ea, self.end_ea)

    @property
    def bitness(self):
        """Segment's Bitness.

        Can be 16, 32 or 64.
        """
        return self.BITNESS_TO_BITS[self.segment_t.bitness]

    @bitness.setter
    def bitness(self, bits):
        try:
            self.segment_t.bitness = self.BITS_TO_BITNESS[bits]
        except KeyError:
            raise exceptions.InvalidBitness("Got {}. Expecting 16, 32 or 64.".format(bits))

    @property
    def next(self):
        """Get the next segment."""
        seg = Segment(segment_t=idaapi.get_next_seg(self.ea))

        if seg.ea <= self.ea:
            raise exceptions.NoMoreSegments("This is the last segment. No segments exist after it.")

        return seg

    @property
    def prev(self):
        """Get the previous segment."""
        seg = Segment(segment_t=idaapi.get_prev_seg(self.ea))

        if seg.ea >= self.ea:
            raise exceptions.NoMoreSegments("This is the first segment. no segments exist before it.")

        return seg

    @property
    def comments(self):
        return Comments(self.segment_t)

    @property
    def size(self):
        return self.end_ea - self.start_ea

    def __repr__(self):
        return ("<Segment(ea=0x{:08X},"
                " name={!r},"
                " size=0x{:08X},"
                " permissions={!r},"
                " bitness={})>").format(self.ea,
                                        self.name,
                                        self.size,
                                        str(self.permissions),
                                        self.bitness)


def segments(seg_type=None):
    """Iterate segments based on type

        Args:
            seg_type: type of segment e.g. SEG_CODE

        Returns:
            iterator of `Segment` objects. if seg_type is None , returns all segments
            otherwise returns only the relevant ones
    """

    for index in range(idaapi.get_segm_qty()):
        seg = Segment(index=index)
        if (seg_type is None) or (seg.type == seg_type):
            yield Segment(index=index)
