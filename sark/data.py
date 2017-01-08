from collections import namedtuple
import idc
import idaapi

import shutil
import itertools
import struct
from awesome.iterator import irange as range
from .core import fix_addresses, get_native_size
from . import exceptions


def Bytes(start=None, end=None):
    start, end = fix_addresses(start, end)

    return itertools.imap(idc.Byte, range(start, end))


def Words(start=None, end=None):
    start, end = fix_addresses(start, end)

    return itertools.imap(idc.Word, range(start, end, 2))


def Dwords(start=None, end=None):
    start, end = fix_addresses(start, end)

    return itertools.imap(idc.Dword, range(start, end, 4))


def Qwords(start=None, end=None):
    start, end = fix_addresses(start, end)

    return itertools.imap(idc.Qword, range(start, end, 8))


def NativeWords(start, end):
    native_size = get_native_size()

    if native_size == 2:
        return Words(start, end)
    elif native_size == 4:
        return Dwords(start, end)
    elif native_size == 8:
        return Qwords(start, end)


def bytes_until(byte=0, start=None, end=None):
    return iter(Bytes(start, end).next, byte)


def words_until(word=0, start=None, end=None):
    return iter(Words(start, end).next, word)


def dwords_until(dword=0, start=None, end=None):
    return iter(Dwords(start, end).next, dword)


def qwords_until(qword=0, start=None, end=None):
    return iter(Qwords(start, end).next, qword)


def native_words_until(native_word=0, start=None, end=None):
    return iter(NativeWords(start, end).next, native_word)


def Chars(start=None, end=None):
    return itertools.imap(chr, Bytes(start, end))


def chars_until(char='\0', start=None, end=None):
    return iter(Chars(start, end).next, char)


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
    return idaapi.get_many_bytes(start, size)


def write_memory(start, data, destructive=False):
    if destructive:
        idaapi.put_many_bytes(start, data)

    else:
        idaapi.patch_many_bytes(start, data)


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
        for patch in patches.itervalues():
            output.seek(patch.fpos)
            patched_byte = chr(patch.patched)
            output.write(patched_byte)


def undefine(start, end):
    idc.MakeUnknown(start, end - start, idc.DOUNK_SIMPLE)


def is_string(ea):
    string_type = idc.GetStringType(idaapi.get_item_head(ea))

    if string_type in (None, -1):
        return False

    return True


def get_string(ea):
    """Read the string at the given ea.

    This function uses IDA's string APIs and does not implement any special logic.
    """
    # We get the item-head because the `GetStringType` function only works on the head of an item.
    string_type = idc.GetStringType(idaapi.get_item_head(ea))

    if string_type is None:
        raise exceptions.SarkNoString("No string at 0x{:08X}".format(ea))

    string = idc.GetString(ea, strtype=string_type)

    if not string:
        raise exceptions.SarkNoString("No string at 0x{:08X}".format(ea))

    return string
