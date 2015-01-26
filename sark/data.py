import idc
import idaapi

import itertools
import struct
from .core import fix_addresses, range


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

    return itertools.imap(idc.Qword, range(start, end, 4))


def bytes_until(byte=0, start=None, end=None):
    return iter(Bytes(start, end).next, byte)


def words_until(word=0, start=None, end=None):
    return iter(Words(start, end).next, word)


def dwords_until(dword=0, start=None, end=None):
    return iter(Dwords(start, end).next, dword)


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


def undefine(start, end):
    idc.MakeUnknown(start, end - start, idc.DOUNK_SIMPLE)