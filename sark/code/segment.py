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
        return idaapi.set_segment_cmt(self._segment, comment, False)

    @property
    def repeat(self):
        return idaapi.get_segment_cmt(self._segment, True)

    @repeat.setter
    def repeat(self, comment):
        return idaapi.set_segment_cmt(self._segment, comment, True)


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
    def segment(self):
        return self._segment

    @property
    def startEA(self):
        return self._segment.startEA

    ea = startEA

    @property
    def endEA(self):
        return self._segment.endEA

    @property
    def name(self):
        return idaapi.get_segm_name(self.segment)


    @property
    def functions(self):
        return functions(self.startEA, self.endEA)

    @property
    def lines(self):
        return lines(self.startEA, self.endEA)

    @property
    def next(self):
        return Segment(idaapi.get_next_seg())

    @property
    def comments(self):
        return Comments(self.segment)

    @property
    def size(self):
        return self.endEA - self.startEA

    def __repr__(self):
        return "<Segment(ea=0x{:08X}, name={!r}, size=0x{:08X})>".format(self.ea, self.name, self.size)


def segments():
    for index in xrange(idaapi.get_segm_qty()):
        yield Segment(index=index)
