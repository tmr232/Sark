from __future__ import print_function

import sark
from dumper_helper import dump_attrs


def main():
    main_function = sark.Function(name='main')

    print(main_function.comments)
    dump_attrs(main_function.comments)

    for line in main_function.lines:
        print(line.comments)
        dump_attrs(line.comments)


if __name__ == '__main__':
    main()
