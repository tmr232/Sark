from collections import namedtuple
import idc
import idaapi

import shutil
import itertools
import struct
from .core import fix_addresses, get_native_size
from . import exceptions


def Bytes(start=None, end=None):
    start, end = fix_addresses(start, end)

    return map(idaapi.get_wide_byte, list(range(start, end)))


def Words(start=None, end=None):
    start, end = fix_addresses(start, end)

    return map(idaapi.get_wide_word, list(range(start, end, 2)))


def Dwords(start=None, end=None):
    start, end = fix_addresses(start, end)

    return map(idaapi.get_wide_dword, list(range(start, end, 4)))


def Qwords(start=None, end=None):
    start, end = fix_addresses(start, end)

    return map(idaapi.get_qword, list(range(start, end, 8)))


def NativeWords(start=None, end=None):
    native_size = get_native_size()

    if native_size == 2:
        return Words(start, end)
    elif native_size == 4:
        return Dwords(start, end)
    elif native_size == 8:
        return Qwords(start, end)


def bytes_until(byte=0, start=None, end=None):
    return iter(Bytes(start, end).__next__, byte)


def words_until(word=0, start=None, end=None):
    return iter(Words(start, end).__next__, word)


def dwords_until(dword=0, start=None, end=None):
    return iter(Dwords(start, end).__next__, dword)


def qwords_until(qword=0, start=None, end=None):
    return iter(Qwords(start, end).__next__, qword)


def native_words_until(native_word=0, start=None, end=None):
    return iter(NativeWords(start, end).__next__, native_word)


def Chars(start=None, end=None):
    return map(chr, Bytes(start, end))


def chars_until(char='\0', start=None, end=None):
    return iter(Chars(start, end).__next__, char)


def read_ascii_string(ea, max_length=None):
    if max_length is None:
        end = None
    else:
        end = ea + max_length
    return "".join(chars_until(start=ea, end=end))


def dword_to_bytes(dword):
    return struct.pack(">L", dword)


def read_memory(start, end):
    size = end - start
    return idaapi.get_bytes(start, size)


def write_memory(start, data, destructive=False):
    if destructive:
        idaapi.put_bytes(start, data)

    else:
        idaapi.patch_bytes(start, data)


PatchedByte = namedtuple("PatchedByte", "ea fpos original patched")


def get_patched_bytes(start=None, end=None):
    start, end = fix_addresses(start, end)

    patched_bytes = dict()

    def collector(ea, fpos, original, patched):
        patched_bytes[ea] = PatchedByte(ea, fpos, original, patched)
        return 0

    idaapi.visit_patched_bytes(start, end, collector)

    return patched_bytes


def apply_patches(output_path=None):
    to_patch = idaapi.get_input_file_path()

    if output_path:
        shutil.copyfile(to_patch, output_path)
        to_patch = output_path

    patches = get_patched_bytes()

    with open(to_patch, "r+b") as output:
        for patch in patches.values():
            output.seek(patch.fpos)
            patched_byte = bytes([patch.patched])
            output.write(patched_byte)


def undefine(start, end):
    idaapi.del_items(start, idaapi.DELIT_SIMPLE, end - start)


def is_string(ea):
    string_type = idc.get_str_type(idaapi.get_item_head(ea))

    if string_type in (None, -1):
        return False

    return True


def get_string(ea):
    """Read the string at the given ea.

    This function uses IDA's string APIs and does not implement any special logic.
    """
    # We get the item-head because the `GetStringType` function only works on the head of an item.
    string_type = idc.get_str_type(idaapi.get_item_head(ea))

    if string_type is None:
        raise exceptions.SarkNoString("No string at 0x{:08X}".format(ea))

    string = idc.get_strlit_contents(ea, strtype=string_type)

    if not string:
        raise exceptions.SarkNoString("No string at 0x{:08X}".format(ea))

    return string
