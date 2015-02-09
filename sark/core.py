import idaapi
import idc
import string
from . import exceptions


def get_func(func_ea):
    if isinstance(func_ea, idaapi.func_t):
        return func_ea
    func = idaapi.get_func(func_ea)
    if func is None:
        raise exceptions.SarkNoFunction("No function at 0x{:08X}".format(func_ea))

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


def set_name(address, name, anyway=False):
    success = idaapi.set_name(address, name, idaapi.SN_NOWARN | idaapi.SN_NOCHECK)
    if success:
        return

    if anyway:
        success = idaapi.do_name_anyway(address, name)
        if success:
            return

        raise exceptions.SarkSetNameFailed("Failed renaming 0x{:08X} to {!r}.".format(address, name))

    raise exceptions.SarkErrorNameAlreadyExists(
        "Can't rename 0x{:08X}. Name {!r} already exists.".format(address, name))


