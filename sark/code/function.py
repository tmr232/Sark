import idaapi
import idautils
import idc
from .base import get_func
from ..core import set_name, get_ea, fix_addresses
from .line import Line
from .xref import Xref


class Comments(object):
    def __init__(self, function):
        self._function = function

    @property
    def regular(self):
        return idaapi.get_func_cmt(self._function._func, False)

    @regular.setter
    def regular(self, comment):
        idaapi.set_func_cmt(self._function._func, comment, False)

    @property
    def repeat(self):
        return idaapi.get_func_cmt(self._function._func, True)

    @repeat.setter
    def repeat(self, comment):
        idaapi.set_func_cmt(self._function._func, comment, True)


    def __repr__(self):
        return ("Comments("
                "func={name},"
                " reqular={regular},"
                " repeat={repeat})").format(
            name=self._function.name,
            regular=repr(self.regular),
            repeat=repr(self.repeat))


class Function(object):
    def __init__(self, ea=None):
        if ea is None:
            ea = idc.here()

        self._func = get_func(ea)
        self._comments = Comments(self)

    @property
    def comments(self):
        return self._comments

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
    def xrefs_from(self):
        for line in self.lines:
            for xref in line.xrefs_from:
                yield xref

    @property
    def drefs_from(self):
        for line in self.lines:
            for ea in line.drefs_from:
                yield ea

    @property
    def crefs_from(self):
        for line in self.lines:
            for ea in line.crefs_from:
                yield ea

    @property
    def xrefs_to(self):
        return map(Xref, idautils.XrefsTo(self.startEA))

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
    def frame_size(self):
        return idaapi.get_frame_size(self._func)


def iter_function_lines(func_ea):
    for line in idautils.FuncItems(get_ea(func_ea)):
        yield Line(line)


def iter_functions(start=None, end=None):
    start, end = fix_addresses(start, end)

    for func_t in idautils.Functions(start, end):
        yield Function(func_t)