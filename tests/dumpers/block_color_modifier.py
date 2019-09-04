from __future__ import print_function

import sark


def main():
    block = next(sark.codeblocks())
    print('Color before change: {}'.format(block.color))

    block.color = 0x1337
    print('Color after change: {}'.format(block.color))

    block.color = None
    print('Color after clear: {}'.format(block.color))


if __name__ == '__main__':
    main()
