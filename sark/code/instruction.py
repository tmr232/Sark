import idaapi
import idautils
import idc

from . import base
from .. import core
from .. import exceptions

OPND_WRITE_FLAGS = {
    0: idaapi.CF_CHG1,
    1: idaapi.CF_CHG2,
    2: idaapi.CF_CHG3,
    3: idaapi.CF_CHG4,
    4: idaapi.CF_CHG5,
    5: idaapi.CF_CHG6,
}

OPND_READ_FLAGS = {
    0: idaapi.CF_USE1,
    1: idaapi.CF_USE2,
    2: idaapi.CF_USE3,
    3: idaapi.CF_USE4,
    4: idaapi.CF_USE5,
    5: idaapi.CF_USE6,
}


class Phrase(object):
    def __init__(self, op_t):
        self.op_t = op_t

        self._initialize()

    def _initialize(self):
        if self.op_t.type not in (idaapi.o_displ, idaapi.o_phrase):
            raise exceptions.OperandNotPhrase('Operand is not of type o_phrase or o_displ.')

        proc_name = idaapi.get_inf_structure().procName
        if proc_name != 'metapc':
            raise exceptions.PhraseProcessorNotSupported(
                'Phrase analysis not supported for processor {}'.format(proc_name))

        specflag1 = self.op_t.specflag1
        specflag2 = self.op_t.specflag2
        scale = 1 << ((specflag2 & 0xC0) >> 6)
        offset = self.op_t.addr

        if specflag1 == 0:
            index = None
            base_ = self.op_t.reg
        elif specflag1 == 1:
            index = (specflag2 & 0x38) >> 3
            base_ = (specflag2 & 0x07) >> 0

            if self.op_t.reg == 0xC:
                if base_ & 4:
                    base_ += 8
                if index & 4:
                    index += 8
        else:
            raise exceptions.PhraseNotSupported('o_displ, o_phrase : Not implemented yet : %x' % specflag1)

        # HACK: This is a really ugly hack. For some reason, phrases of the form `[esp + ...]` (`sp`, `rsp` as well)
        # set both the `index` and the `base` to `esp`. This is not significant, as `esp` cannot be used as an
        # index, but it does cause issues with the parsing.
        # This is only relevant to Intel architectures.
        if (index == base_ == idautils.procregs.sp.reg) and (scale == 1):
            index = None

        self.scale = scale
        self.index_id = index
        self.base_id = base_
        self.offset = offset

    @property
    def base(self):
        if self.base_id is None:
            return None
        return base.get_register_name(self.base_id)

    @property
    def index(self):
        if self.index_id is None:
            return None
        return base.get_register_name(self.index_id)

    def __repr__(self):
        phrase = []
        if self.base_id is not None:
            phrase.append(self.base)
        if self.index_id is not None:
            if phrase:
                phrase.append('+')
            phrase.append('{index}*{scale}'.format(index=self.index, scale=self.scale))
        if self.offset:
            offset = self.offset
            sign = '+'
            if core.is_signed(offset):
                offset = offset - (1 << (8 * core.get_native_size()))
                sign = '-'
            value = '{:X}'.format(abs(offset))
            phrase.append('{sign}{prefix}{value}{suffix}'.format(sign=sign if phrase or offset < 0 else '',
                                                                 prefix='0' if value[0].isalpha() else '',
                                                                 value=value,
                                                                 suffix='h' if abs(offset) > 9 else ''))

        return '[{}]'.format(''.join(phrase))


class OperandType(object):
    TYPES = {
        idaapi.o_void: "No_Operand",
        idaapi.o_reg: "General_Register",
        idaapi.o_mem: "Direct_Memory_Reference",
        idaapi.o_phrase: "Memory_Phrase",
        idaapi.o_displ: "Memory_Displacement",
        idaapi.o_imm: "Immediate_Value",
        idaapi.o_far: "Immediate_Far_Address",
        idaapi.o_near: "Immediate_Near_Address",
        idaapi.o_idpspec0: "Processor_specific_type",
        # There can be more processor specific types!
    }

    def __init__(self, type_):
        super(OperandType, self).__init__()

        self._type = type_

    @property
    def type(self):
        """Raw `type` value

        Use this if you need to pass the operand type around as a number.
        """
        return self._type

    @property
    def name(self):
        """Name of the xref type."""
        return self.TYPES.get(self._type, self.TYPES[idaapi.o_idpspec0])

    def __repr__(self):
        return self.name

    @property
    def is_void(self):
        return self._type == idaapi.o_void

    @property
    def is_reg(self):
        return self._type == idaapi.o_reg

    @property
    def is_mem(self):
        return self._type == idaapi.o_mem

    @property
    def is_phrase(self):
        return self._type == idaapi.o_phrase

    @property
    def is_displ(self):
        return self._type == idaapi.o_displ

    @property
    def is_imm(self):
        return self._type == idaapi.o_imm

    @property
    def is_far(self):
        return self._type == idaapi.o_far

    @property
    def is_near(self):
        return self._type == idaapi.o_near

    @property
    def is_special(self):
        return self._type >= idaapi.o_idpspec0

    @property
    def has_reg(self):
        return self._type in (idaapi.o_reg, idaapi.o_displ, idaapi.o_phrase)

    @property
    def has_phrase(self):
        return self._type in (idaapi.o_phrase, idaapi.o_displ)


class Operand(object):
    def __init__(self, operand, ea, insn, write=False, read=False):
        self._operand = operand
        self._write = write
        self._read = read
        self._type = OperandType(operand.type)
        self._ea = ea
        # We have to save the `insn_t` object referenced to make sure the `op_t` object is not released on the C side.
        self._insn = insn
        try:
            self._phrase = Phrase(operand)
        except exceptions.PhraseError:
            self._phrase = None

    @property
    def n(self):
        """Index of the operand in the instruction."""
        return self._operand.n

    @property
    def type(self):
        """Operand type."""
        return self._type

    @property
    def has_displacement(self):
        return base.operand_has_displacement(self._operand)

    @property
    def displacement(self):
        return base.operand_get_displacement(self._operand)

    offset = displacement

    @property
    def op_t(self):
        return self._operand

    @property
    def flags(self):
        return self._operand.flags

    @property
    def dtyp(self):
        return self._operand.dtyp

    @property
    def imm(self):
        return self._operand.value

    value = imm

    @property
    def addr(self):
        return self._operand.addr

    def has_reg(self, reg_name):
        return any(reg == reg_name for reg in self.regs)

    @property
    def size(self):
        """Size of the operand."""
        return base.dtyp_to_size(self._operand.dtyp)

    @property
    def is_read(self):
        """Is the operand value used in the instruction."""
        return self._read

    @property
    def is_write(self):
        """Is the operand value changed in the instruction."""
        return self._write

    @property
    def reg_id(self):
        """ID of the register used in the operand."""
        return self._operand.reg

    @property
    def reg(self):
        """Name of the register used in the operand."""
        if self.type.is_displ or self.type.is_phrase:
            size = core.get_native_size()
            return base.get_register_name(self.reg_id, size)

        if self.type.is_reg:
            return base.get_register_name(self.reg_id, self.size)

        else:
            raise exceptions.SarkOperandWithoutReg("Operand does not have a register.")

    @property
    def regs(self):
        if self.type.has_phrase:
            return set(reg for reg in (self.base, self.index) if reg)
        elif self.type.is_reg:
            return {base.get_register_name(self.reg_id, self.size)}
        else:
            return set()

    @property
    def text(self):
        return idc.GetOpnd(self._ea, self.n)

    def __str__(self):
        return self.text

    def __repr__(self):
        return "<Operand(n={}, text={!r})>".format(self.n, str(self))

    @property
    def base(self):
        if self._phrase:
            return self._phrase.base
        return self.reg

    @property
    def scale(self):
        if self._phrase:
            return self._phrase.scale
        return None

    @property
    def index(self):
        if self._phrase:
            return self._phrase.index
        return None

    @property
    def offset(self):
        if self._phrase:
            return self._phrase.offset
        return self.addr


class IndexingMode(object):
    def __init__(self, pre=False, post=False):
        self.pre = pre
        self.post = post

    @property
    def is_pre(self):
        return self.pre

    @property
    def is_post(self):
        return self.post

    @property
    def is_none(self):
        return not (self.pre or self.post)

    def __nonzero__(self):
        return self.pre or self.post


class Instruction(object):
    def __init__(self, ea):
        self._ea = ea
        self._insn = idautils.DecodeInstruction(ea)

        if self._insn is None:
            raise exceptions.SarkNoInstruction("No Instruction at 0x{:08X}.".format(ea))

        self._operands = self._make_operands()

    def _make_operands(self):
        operands = []
        for index, operand in enumerate(self._insn.Operands):
            if operand.type == idaapi.o_void:
                break  # No more operands.
            operands.append(Operand(operand,
                                    self._ea,
                                    insn=self._insn,
                                    write=self.is_operand_written_to(index),
                                    read=self.is_operand_read_from(index)))
        return operands

    @property
    def operands(self):
        """Instruction's Operands."""
        return self._operands

    @property
    def feature(self):
        """Canonical Features"""
        return self._insn.get_canon_feature()

    @property
    def mnem(self):
        """Instruction Mnemonic"""
        return self._insn.get_canon_mnem()

    def has_reg(self, reg_name):
        """Check if a register is used in the instruction."""
        return any(operand.has_reg(reg_name) for operand in self.operands)

    def is_operand_written_to(self, operand_index):
        """Check if an operand is written to (destination operand)."""
        return bool(self.feature & OPND_WRITE_FLAGS[operand_index])

    def is_operand_read_from(self, operand_index):
        """Check if an operand is read from (source operand)."""
        return bool(self.feature & OPND_READ_FLAGS[operand_index])

    @property
    def regs(self):
        """Names of all registers used by the instruction."""
        regs = set()
        for operand in self.operands:
            if not operand.type.has_reg:
                continue
            regs.update(operand.regs)
        return regs

    @property
    def is_call(self):
        """Is the instruction a call instruction."""
        return idaapi.is_call_insn(self._ea)

    @property
    def is_ret(self):
        """Is the instruction a return instruction."""
        return idaapi.is_ret_insn(self._ea)

    @property
    def is_indirect_jump(self):
        """Is the instruction an indirect jump instruction."""
        return idaapi.is_indirect_jump_insn(self._ea)

    @property
    def insn_t(self):
        return self._insn

    @property
    def indexing_mode(self):
        if idaapi.get_inf_structure().procName != 'ARM':
            return IndexingMode()

        return IndexingMode(pre=bool(self.insn_t.auxpref & 0x20),
                            post=bool(self.insn_t.auxpref & 0x80))
