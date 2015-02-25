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


class Operand(object):
    def __init__(self, operand, write=False, read=False):
        self._operand = operand
        self._write = write
        self._read = read

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
        return base.dtyp_to_size(self._operand.dtyp)

    @property
    def is_read(self):
        return self._read

    @property
    def is_write(self):
        return self._write

    @property
    def reg_id(self):
        return self._operand.reg

    @property
    def reg(self):
        return base.get_register_name(self.reg_id, self.size)


class Instruction(object):
    def __init__(self, ea):
        self._ea = ea
        self._inst = idautils.DecodeInstruction(ea)
        self._operands = self._make_operands()

    def _make_operands(self):
        operands = []
        for index, operand in enumerate(self._inst.Operands):
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
        return self._inst.get_canon_feature()

    def has_reg(self, reg_name):
        return any(operand.has_reg(reg_name) for operand in self.operands)

    def is_operand_written_to(self, operand_index):
        return bool(self.feature & OPND_WRITE_FLAGS[operand_index])

    def is_operand_read_from(self, operand_index):
        return bool(self.feature & OPND_READ_FLAGS[operand_index])

    @property
    def regs(self):
        return [operand.reg for operand in self.operands]