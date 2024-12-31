import idaapi
import idc
import ida_ida
import ida_search
import string
from . import exceptions


def get_func(func_ea):
    """get_func(func_t or ea) -> func_t

    Take an IDA function (``idaapi.func_t``) or an address (EA) and return
    an IDA function object.

    Use this when APIs can take either a function or an address.

    Args:
        func_ea: ``idaapi.func_t`` or ea of the function.

    Returns:
        An ``idaapi.func_t`` object for the given address. If a ``func_t`` is
        provided, it is returned.
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

    Args:
        func_ea: `idaapi.func_t` or EA.

    Returns:
        The ea.
    """
    if isinstance(func_ea, idaapi.func_t):
        return func_ea.start_ea
    return func_ea


def add_func(func_ea,func_end=idaapi.BADADDR):
    return idaapi.add_func(func_ea,func_end)

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
        direction = ida_search.SEARCH_DOWN
    else:
        direction = ida_search.SEARCH_UP

    current = ida_search.find_binary(start, end, query, 16, direction)
    while current < end:
        yield current
        current = ida_search.find_binary(current + 1, end, query, 16, direction)


def fix_addresses(start=None, end=None):
    """Set missing addresses to start and end of IDB.

    Take a start and end addresses. If an address is None or `BADADDR`,
    return start or end addresses of the IDB instead.

    Args
        start: Start EA. Use `None` to get IDB start.
        end:  End EA. Use `None` to get IDB end.

    Returns:
        (start, end)
    """
    if start in (None, idaapi.BADADDR):
        start = ida_ida.inf_get_min_ea()

    if end in (None, idaapi.BADADDR):
        end = ida_ida.inf_get_max_ea()

    return start, end


def set_name(address, name, anyway=False):
    """Set the name of an address.

    Sets the name of an address in IDA.
    If the name already exists, check the `anyway` parameter:

        True - Add `_COUNTER` to the name (default IDA behaviour)
        False - Raise an `exceptions.SarkErrorNameAlreadyExists` exception.


    Args
        address: The address to rename.
        name: The desired name.
        anyway: Set anyway or not. Defualt ``False``.
    """
    success = idaapi.set_name(address, name, idaapi.SN_NOWARN | idaapi.SN_NOCHECK)
    if success:
        return

    if anyway:
        success = idaapi.force_name(address, name)
        if success:
            return

        raise exceptions.SarkSetNameFailed("Failed renaming 0x{:08X} to {!r}.".format(address, name))

    raise exceptions.SarkErrorNameAlreadyExists(
        "Can't rename 0x{:08X}. Name {!r} already exists.".format(address, name))


def is_same_function(ea1, ea2):
    """Are both addresses in the same function?"""
    func1 = idaapi.get_func(ea1)
    func2 = idaapi.get_func(ea2)
    # This is bloated code. `None in (func1, func2)` will not work because of a
    # bug in IDAPython in the way functions are compared.
    if any(func is None for func in (func1, func2)):
        return False

    return func1.start_ea == func2.start_ea


def get_name_or_address(ea):
    name = idaapi.get_ea_name(ea, idaapi.GN_VISIBLE)
    if name:
        name = repr(name)
    else:
        name = "0x{:08X}".format(ea)

    return name


def get_native_size():
    """Get the native word size in normal 8-bit bytes."""
    bits = ida_ida.inf_get_app_bitness()
    if bits == 64:
        return 8
    elif bits == 32:
        return 4
    else:
        return 2


def get_fileregion_offset(ea):
    file_offset = idaapi.get_fileregion_offset(ea)
    if file_offset == -1:
        raise exceptions.NoFileOffset("Address 0x{:08X} is not mapped to any file offset.".format(ea))

    return file_offset

def is_function(ea):
    try:
        get_func(ea)
        return True
    except exceptions.SarkNoFunction:
        return False


def is_signed(number, size=None):
    if not size:
        size = get_native_size()
    return number & (1 << ((8 * size) - 1))


