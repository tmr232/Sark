from collections import namedtuple
import idaapi


class Registers(object):
    """
    Wrapper around IDA's debug registers.

    Enables easy querying of the debug registers API (`idaapi.dbg_get_registers`) to get
    register info, such as the names of the instruction pointer and the stack pointer.

    Usage (on x86):
        >>> print(Registers().ip.name)
        eip

        >>> print(Registers().sp.name)
        esp
    """
    REGISTER_READONLY = 0x001  # the user can't modify the current value of this register
    REGISTER_IP = 0x002  # instruction pointer
    REGISTER_SP = 0x004  # stack pointer
    REGISTER_FP = 0x008  # frame pointer
    REGISTER_ADDRESS = 0x010  # may contain an address
    REGISTER_CS = 0x020  # code segment
    REGSITER_SS = 0x040  # stack segment
    REGISTER_NOLF = 0x080  # displays this register without returning to the next line
    REGISTER_CUSTFMT = 0x100  # allowing the next register to be displayed to its right (on the same line)
    # register should be displayed using a custom data format.

    RegisterInfo = namedtuple("RegisterInfo", "name, flags, cls, dtyp, bit_strings, bit_strings_default_mask")

    def __init__(self):
        reg_infos = idaapi.dbg_get_registers()
        if not reg_infos:
            raise RuntimeError("Debugger not present.")

        self._reg_infos = [self.RegisterInfo(*reg_info) for reg_info in reg_infos]

    def get_by_flags(self, flags):
        """Iterate all register infos matching the given flags."""
        for reg in self._reg_infos:
            if reg.flags & flags == flags:
                yield reg

    def get_single_by_flags(self, flags):
        """Get the register info matching the flag. Raises ValueError if more than one are found."""
        regs = list(self.get_by_flags(flags))
        if len(regs) != 1:
            raise ValueError("Flags do not return unique resigter. {!r}", regs)

        return regs[0]

    @property
    def ip(self):
        """Instruction Pointer"""
        return self.get_single_by_flags(self.REGISTER_IP)

    pc = ip

    @property
    def sp(self):
        """Stack Pointer"""
        return self.get_single_by_flags(self.REGISTER_SP)

    @property
    def fp(self):
        """Frame Pointer"""
        return self.get_single_by_flags(self.REGISTER_FP)