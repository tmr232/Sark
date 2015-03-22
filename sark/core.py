import idaapi
import idc
import string
from . import exceptions


def get_func(func_ea):
    """get_func(func_t or ea) -> func_t

    Take an IDA function (`idaapi.func_t`) or an address (EA) and return
    an IDA function object.

    Use this when APIs can take either a function or an address.

    :param func_ea: `idaapi.func_t` or ea of the function.
    :return: `idaapi.func_t`
    """
    if isinstance(func_ea, idaapi.func_t):
        return func_ea
    func = idaapi.get_func(func_ea)
    if func is None:
        raise exceptions.SarkNoFunction("No function at 0x{:08X}".format(func_ea))

    return func


def get_ea(func_ea):
    """get_ea(func_t or ea) -> ea

    Same as `get_func`, but returns the EA.

    :param func_ea: `idaapi.func_t` or EA.
    :return: The ea.
    """
    if isinstance(func_ea, idaapi.func_t):
        return func_ea.startEA
    return func_ea


def is_string_printable(string_):
    """Check if a string is printable"""
    return set(string_) - set(string.printable)


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
    """Set missing addresses to start and end of IDB.

    Take a start and end addresses. If an address is None or `BADADDR`,
    return start or end addresses of the IDB instead.

    :param start: Start EA. Use `None` to get IDB start.
    :param end:  End EA. Use `None` to get IDB end.
    :return: (start, end)
    """
    if start in (None, idaapi.BADADDR):
        start = idaapi.cvar.inf.minEA

    if end in (None, idaapi.BADADDR):
        end = idaapi.cvar.inf.maxEA

    return start, end


def set_name(address, name, anyway=False):
    """Set the name of an address.

    Sets the name of an address in IDA.
    If the name already exists, check the `anyway` parameter:

        True - Add `_COUNTER` to the name (default IDA behaviour)
        False - Raise an `exceptions.SarkErrorNameAlreadyExists` exception.

    :param address: The address to rename.
    :param name: The desired name.
    :param anyway: Set anyway or not. Defualt `False`.
    :return: None
    """
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


