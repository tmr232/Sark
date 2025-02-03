import itertools
from typing import Optional

import ida_bytes
import ida_ua

import sark
from keystone import Ks, KS_MODE_64, KS_ARCH_X86

from sark.exceptions import SarkOperandWithoutReg

REGISTERS_64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"] + [
    f"r{i}" for i in range(8, 16)
]


def assemble(line: str) -> bytes:
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, _count = ks.asm(line)
    return bytes(encoding)


def lea(base: Optional[str], index: Optional[str], scale: int, offset: int) -> str:
    assert scale >= 1

    parts = []

    if base:
        parts.append(base)

    if index:
        if base:
            parts.append("+")
        parts.append(f"{index} * {scale}")

    if offset:
        if base or index:
            parts.append("+")
        parts.append(str(offset))

    phrase = " ".join(parts)

    return f"lea rax, [{phrase}]"


def main():
    print("Diffing generated and parsed phrases.")
    print("Any line printed indicates an error.")
    print()
    text_segment = sark.Segment(name=".text")

    # First, make room for our code!
    sark.data.undefine(text_segment.start_ea, text_segment.end_ea)

    ea = text_segment.start_ea

    for base, index, scale, offset in itertools.product(
        REGISTERS_64 + [None], REGISTERS_64 + [None], [1, 2, 4, 8], [0, 1, 255]
    ):
        if index is None and scale != 1:
            continue
        if index == "rsp":
            # RSP is ignored
            continue
        if base is None and index is None:
            continue

        line = lea(base, index, scale, offset)
        try:
            asm = assemble(line)
        except Exception:
            print("Invalid: ", line)
            raise

        ida_bytes.patch_bytes(ea, asm)
        ida_ua.create_insn(ea)

        op = sark.Line(ea).insn.operands[1]
        try:
            try:
                parsed_base = op.base
            except SarkOperandWithoutReg:
                parsed_base = None
            parsed_index = op.index
            parsed_scale = op.scale
            parsed_offset = op.offset
        except Exception:
            print(line)
            raise

        flags = (
            ("B" if parsed_base != base else "-")
            + ("I" if parsed_index != index else "-")
            + ("S" if parsed_scale != scale else "-")
            + ("O" if parsed_offset != offset else "-")
        )

        if flags != "----":
            print(f"{flags} | {line} | {parsed_index=} | {parsed_scale=}")

        sark.data.undefine(ea, ea + ida_bytes.get_item_size(ea))

    print()
    print("Done.")


if __name__ == "__main__":
    main()
