import idaapi
import idautils

from . import base

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
        return self.TYPES[self._type]

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


class Operand(object):
    def __init__(self, operand, write=False, read=False):
        self._operand = operand
        self._write = write
        self._read = read
        self._type = OperandType(operand.type)

    @property
    def n(self):
        """Index of the operand in the instruction."""
        return self._operand.n

    @property
    def type(self):
        return self._type

    @property
    def has_displacement(self):
        return base.operand_has_displacement(self._operand)

    @property
    def displacement(self):
        return base.operand_get_displacement(self._operand)

    def has_reg(self, reg_name):
        return base.is_reg_in_operand(self._operand, reg_name)

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
        return base.get_register_name(self.reg_id, self.size)


class Instruction(object):
    def __init__(self, ea):
        self._ea = ea
        self._insn = idautils.DecodeInstruction(ea)
        self._operands = self._make_operands()

    def _make_operands(self):
        operands = []
        for index, operand in enumerate(self._insn.Operands):
            if operand.type == idaapi.o_void:
                break  # No more operands.
            operands.append(Operand(operand,
                                    write=self.is_operand_written_to(index),
                                    read=self.is_operand_read_from(index)))
        return operands


    @property
    def operands(self):
        return self._operands

    @property
    def feature(self):
        return self._insn.get_canon_feature()

    @property
    def mnem(self):
        return self._insn.get_canon_mnem()

    def has_reg(self, reg_name):
        return any(operand.has_reg(reg_name) for operand in self.operands)

    def is_operand_written_to(self, operand_index):
        return bool(self.feature & OPND_WRITE_FLAGS[operand_index])

    def is_operand_read_from(self, operand_index):
        return bool(self.feature & OPND_READ_FLAGS[operand_index])

    @property
    def regs(self):
        """Names of all registers used by the instruction."""
        return set(operand.reg for operand in self.operands)