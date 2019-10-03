from __future__ import print_function

import sark
from dumper_helper import dump_attrs

def ignore_sark_exception(e):
    return isinstance(e, sark.exceptions.SarkException)

def main():
    function_names = ['main', '__libc_csu_init']
    for name in function_names:
        function = sark.Function(name=name)
        for line in function.lines:
            print('*' * 70)
            print(line)
            insn = line.insn
            print(insn)
            dump_attrs(insn)
            print()
            for operand in insn.operands:
                print('-'*70)
                print(operand)
                dump_attrs(operand, handle_execption=ignore_sark_exception)



if __name__ == '__main__':
    main()
