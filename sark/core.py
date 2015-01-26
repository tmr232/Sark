import idaapi
import idc
import string

from . import exceptions


def get_func(func_ea):
    if isinstance(func_ea, idaapi.func_t):
        return func_ea
    func = idaapi.get_func(func_ea)
    if func is None:
        raise exceptions.SarkNoFunction()

    return func


def get_ea(func_ea):
    if isinstance(func_ea, idaapi.func_t):
        return func_ea.startEA
    return func_ea


def is_string_printable(string_):
    return all(char in string.printable for char in string_)


def string_to_query(string_):
    if is_string_printable(string_):
        return '"{}"'.format(string_)

    return " ".join(char.encode("hex") for char in string_)


def iter_find_string(query, start=None, end=None, down=True):
    query = string_to_query(query)
    return iter_find_query(query, start, end, down)


def iter_find_query(query, start=None, end=None, down=True):
    start, end = fix_addresses(start, end)

    if down:
        direction = idc.SEARCH_DOWN
    else:
        direction = idc.SEARCH_UP

    current = idc.FindBinary(start, direction, query)
    while current < end:
        yield current
        current = idc.FindBinary(current + 1, direction, query)


def fix_addresses(start=None, end=None):
    if start in (None, idaapi.BADADDR):
        start = idaapi.cvar.inf.minEA
    if end in (None, idaapi.BADADDR):
        end = idaapi.cvar.inf.maxEA

    return start, end


def range(start, end=None, step=1):
    if end is None:
        end = start
        start = 0

    if cmp(start, end) * step >= 0:
        return

    value = start
    while cmp(start, end) * cmp(value, end) > 0:
        yield value
        value += step


def ilen(iterator):
    return sum(1 for item in iterator)