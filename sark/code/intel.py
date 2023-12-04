"""
Parsing x86_64 operand phrases.

This is a partial Python port of the functionality in `intel.hpp`.
For more information and documentation, see `intel.hpp` in the IDA SDK.

The names and structure here are ment to closely resemble the C++ code,
to make future changes easier.
"""

import enum

import ida_ua

from sark.exceptions import InvalidPhraseRegisters


class RegNo(enum.IntEnum):
    R_none = -1
    R_ax = 0
    R_cx = 1
    R_dx = 2
    R_bx = 3
    R_sp = 4
    R_bp = 5
    R_si = 6
    R_di = 7
    R_r8 = 8
    R_r9 = 9
    R_r10 = 10
    R_r11 = 11
    R_r12 = 12
    R_r13 = 13
    R_r14 = 14
    R_r15 = 15


class Aux(enum.IntFlag):
    Use32 = 0x8
    Use64 = 0x10
    NatAd = 0x1000


REX_X = 2  # sib index field extension
REX_B = 1  # modrm r/m, sib base, or opcode reg fields extension


INDEX_NONE = 4  # no index register is present


def ad16(insn: ida_ua.insn_t) -> bool:
    p = insn.auxpref & (Aux.Use32 | Aux.Use64 | Aux.NatAd)
    return p == Aux.NatAd or p == Aux.Use32


def hasSIB(op: ida_ua.op_t) -> int:
    return op.specflag1


def sib(op: ida_ua.op_t) -> int:
    return op.specflag2


def rex(insn: ida_ua.insn_t) -> int:
    return insn.insnpref


def sib_base(insn: ida_ua.insn_t, x: ida_ua.op_t):
    base = sib(x) & 7
    if rex(insn) & REX_B:
        base |= 8
    return base


def is_vsib(insn):
    # This seems to be for AVX instructions, and is annoying to implement.
    # So I'm ignoring this for now.
    return False


def sib_index(insn, x):
    index = (sib(x) >> 3) & 7
    if rex(insn) & REX_X:
        index |= 8
    if is_vsib(insn):
        # This is a lot of code to write, and I don't know if there's
        # an actual need for this.
        # If anyone wants this - PRs are welcome!
        raise NotImplementedError("AVX support is currently not implemented.")
    return index


def sib_scale(x):
    scale = (sib(x) >> 6) & 3
    return scale


def x86_scale(x):
    if hasSIB(x):
        return sib_scale(x)
    return 0


def x86_index_reg(insn, x):
    if hasSIB(x):
        idx = sib_index(insn, x)
        if idx != INDEX_NONE:
            return idx
        return RegNo.R_none
    if not ad16(insn):
        return RegNo.R_none
    if x.phrase == 0 or x.phrase == 2:
        return RegNo.R_si
    if x.phrase == 1 or x.phrase == 3:
        return RegNo.R_di
    if x.phrase in (4, 5, 6, 7):
        return RegNo.R_none
    raise InvalidPhraseRegisters("Could not parse phrase index register.")


def x86_base_reg(insn, x):
    if hasSIB(x):
        if x.type == ida_ua.o_mem:
            return RegNo.R_none
        return sib_base(insn, x)  # base register is encoded in the SIB
    elif not ad16(insn):
        return x.phrase  # 'phrase' contains the base register number
    elif x.phrase == RegNo.R_none:
        return RegNo.R_sp
    if x.phrase == 0 or x.phrase == 1 or x.phrase == 7:  # [BX+SI], [BX+DI], [BX]
        return RegNo.R_bx
    elif x.phrase == 2 or x.phrase == 3 or x.phrase == 6:  # [BP+SI], [BP+DI], [BP]
        return RegNo.R_bp
    elif x.phrase == 4:  # [SI]
        return RegNo.R_si
    elif x.phrase == 5:  # [DI]
        return RegNo.R_di
    else:
        raise InvalidPhraseRegisters("Could not parse phrase base register.")
