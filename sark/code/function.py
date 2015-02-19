import idaapi
import idautils
import idc
from .base import get_func
from ..core import set_name, get_ea, fix_addresses
from .line import Line


class Function(object):
    def __init__(self, ea):
        self._func = get_func(ea)

    def __eq__(self, other):
        try:
            return self.startEA == other.startEA
        except AttributeError:
            return False

    def __hash__(self):
        return self.startEA

    @property
    def lines(self):
        return iter_function_lines(self._func)

    @property
    def startEA(self):
        return self._func.startEA

    @property
    def endEA(self):
        return self._func.endEA

    @property
    def xrefs_to(self):
        return idautils.XrefsTo(self.startEA)

    @property
    def drefs_to(self):
        return idautils.DataRefsTo(self.startEA)

    @property
    def crefs_to(self):
        return idautils.CodeRefsTo(self.startEA, 1)

    @property
    def name(self):
        return idc.Name(self.startEA)

    @name.setter
    def name(self, name):
        self.set_name(name)

    def set_name(self, name, anyway=False):
        set_name(self.startEA, name, anyway=anyway)

    def __repr__(self):
        return 'Function(name="{}", addr=0x{:08X})'.format(self.name, self.startEA)

    @property
    def comment(self):
        return idaapi.get_func_cmt(self._func, False)

    @comment.setter
    def comment(self, value):
        idaapi.set_func_cmt(self._func, value, False)

    @property
    def frame_size(self):
        return idaapi.get_frame_size(self._func)


def iter_function_lines(func_ea):
    for line in idautils.FuncItems(get_ea(func_ea)):
        yield Line(line)

def iter_functions(start=None, end=None):
    start, end = fix_addresses(start, end)

    for func_t in idautils.Functions(start, end):
        yield Function(func_t)